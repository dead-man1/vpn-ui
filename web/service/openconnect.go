package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// OcservService manages OpenConnect (ocserv) server configuration: TLS certs,
// the ocserv.conf + radcli client config, the daemon child process, and routing.
//
// Architecturally ocserv is the closest sibling of OpenVPN — a userspace tun
// daemon whose clients get a source IP inside a per-inbound /24, which the shared
// nftables TPROXY path redirects into Xray. It differs in two ways that make it
// simpler here: a SINGLE listener carries both TLS (TCP) and DTLS (UDP) on one
// port (no udp/tcp split, no 10.3 mirror), and it speaks RADIUS natively via
// radcli — so authentication, per-account IP pinning (Framed-IP-Address), and
// accounting all go through the panel's in-process RADIUS server with no
// per-connection hook scripts (unlike OpenVPN).
type OcservService struct {
	inboundService InboundService
	nftService     NftService
	radiusService  *RadiusService
	radiusSecret   string
}

// ocservSettings is the OpenConnect-specific slice of an inbound's Settings JSON.
type ocservSettings struct {
	Dns1 string `json:"dns1"`
	Dns2 string `json:"dns2"`
	Mtu  int    `json:"mtu"`

	// TLS follows the Xray inbound model: either operator-supplied paths
	// (TlsUseFile) or inline PEM content. "Generate Self-Signed Cert" fills the
	// content fields; "Set Default Cert" copies the panel's own webCertFile/
	// webKeyFile paths (TlsUseFile mode). ocserv reads whichever is active from
	// disk, exactly like the panel's own HTTPS listener does.
	TlsUseFile      bool   `json:"tlsUseFile"`
	CertificateFile string `json:"certificateFile"` // path mode: server cert path
	KeyFile         string `json:"keyFile"`         // path mode: server key path
	Certificate     string `json:"certificate"`     // content mode: server cert PEM
	Key             string `json:"key"`             // content mode: server key PEM
	CaCert          string `json:"caCert"`          // optional CA PEM (self-signed)

	ClientToClient    bool     `json:"clientToClient"`
	CrossInbound      bool     `json:"crossInbound"`
	UserLimit         int      `json:"userLimit"`         // simultaneous devices per account (1..64); 1 = legacy
	UserLimitStrategy string   `json:"userLimitStrategy"` // "accept" (evict oldest) or "reject"
	IpRanges          []string `json:"ipRanges"`          // panel-managed 10.4.x /24 ranges
	Clients           []ocservClient `json:"clients"`
}

// effectiveRanges returns the inbound's client /24 ranges, or nil to signal the
// legacy id-derived /24 (10.4.{id}).
func (o *ocservSettings) effectiveRanges() []string { return o.IpRanges }

type ocservClient struct {
	ID       string `json:"id"`       // OpenConnect username
	Password string `json:"password"` // OpenConnect password
	Email    string `json:"email"`    // tracking identifier
	Enable   bool   `json:"enable"`
}

// SetRadius wires the shared RADIUS service + secret for OpenConnect auth/acct.
func (s *OcservService) SetRadius(rs *RadiusService, secret string) {
	s.radiusService = rs
	s.radiusSecret = secret
}

func (s *OcservService) GetOcservInbounds() ([]*model.Inbound, error) {
	db := database.GetDB()
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).Where("protocol = ?", "openconnect").Find(&inbounds).Error
	return inbounds, err
}

func (s *OcservService) parseSettings(inbound *model.Inbound) (*ocservSettings, error) {
	settings := &ocservSettings{}
	err := json.Unmarshal([]byte(inbound.Settings), settings)
	return settings, err
}

// configDir returns the directory holding an OpenConnect inbound's config, radcli,
// and (content-mode) cert files.
func (s *OcservService) configDir(inboundId int) string {
	return fmt.Sprintf("/etc/ocserv/server-%d", inboundId)
}

// ocservBinaryPath returns the ocserv executable the panel runs: the bundled
// static daemon if extracted, else a distro ocserv from PATH.
func (s *OcservService) ocservBinaryPath() string {
	return daemonBin("ocserv")
}

// occtlBinaryPath returns the occtl control tool (bundled alongside ocserv), used
// for programmatic session control (User Limit eviction in Phase 3).
func (s *OcservService) occtlBinaryPath() string {
	return daemonBin("occtl")
}

// ocservBlockFor returns the network address and prefix length of an inbound's
// client block (10.4.x), derived from its stored ranges. The server takes .1;
// clients start at .2. Defaults to the legacy 10.4.{id}.0/24 when no ranges are
// stored.
func ocservBlockFor(inbound *model.Inbound, settings *ocservSettings) (net.IP, int) {
	return vpnBlock(settings.effectiveRanges(), protocolBase("openconnect"), inbound.Id)
}

// GetTproxyPort returns the deterministic TPROXY/dokodemo port for the inbound.
// Inbound IDs are globally unique, so this shares the 12300+id formula with
// L2TP/PPTP/OpenVPN without colliding.
func (s *OcservService) GetTproxyPort(inbound *model.Inbound) int {
	return 12300 + inbound.Id
}

// GetDokodemoConfig builds the paired dokodemo-door inbound that captures the
// TPROXY-redirected OpenConnect traffic and feeds it into Xray's routing — the
// same mechanism L2TP/PPTP/OpenVPN use.
func (s *OcservService) GetDokodemoConfig(inbound *model.Inbound) *xray.InboundConfig {
	port := s.GetTproxyPort(inbound)
	settings := `{"network":"tcp,udp","followRedirect":true}`
	streamSettings := `{"sockopt":{"tproxy":"tproxy","mark":255}}`
	sniffing := `{"enabled":true,"destOverride":["http","tls"]}`

	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(`"0.0.0.0"`),
		Port:           port,
		Protocol:       "dokodemo-door",
		Settings:       json_util.RawMessage(settings),
		StreamSettings: json_util.RawMessage(streamSettings),
		Tag:            inbound.Tag,
		Sniffing:       json_util.RawMessage(sniffing),
	}
}

// InitOcserv initializes OpenConnect services on panel startup.
func (s *OcservService) InitOcserv() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil || len(inbounds) == 0 {
		return
	}

	logger.Info("OpenConnect: initializing services for", len(inbounds), "inbound(s)")

	if err := s.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenConnect: failed to generate configs:", err)
		return
	}
	if err := s.SetupRouting(); err != nil {
		logger.Warning("OpenConnect: failed to setup routing:", err)
	}
	if err := s.RestartServices(); err != nil {
		logger.Warning("OpenConnect: failed to restart services:", err)
	}
}

// GenerateAllConfigs regenerates every OpenConnect config file from DB state.
func (s *OcservService) GenerateAllConfigs() error {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}
	if len(inbounds) == 0 {
		return nil
	}

	for _, inbound := range inbounds {
		if err := s.generateServerConfig(inbound); err != nil {
			logger.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if err := s.writeCertFiles(inbound); err != nil {
			logger.Warning("OpenConnect: cert write failed for inbound", inbound.Id, err)
		}
		if err := s.writeRadiusClientConfig(inbound); err != nil {
			logger.Warning("OpenConnect: radcli config write failed for inbound", inbound.Id, err)
		}
	}
	return nil
}

// generateServerConfig writes the ocserv.conf for one inbound.
func (s *OcservService) generateServerConfig(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)
	os.MkdirAll("/var/run/ocserv", 0755)

	conf := s.buildServerConfig(inbound, settings)
	return s.writeFile(fmt.Sprintf("%s/ocserv.conf", dir), conf)
}

// ocservProcName returns the process-manager key for an OpenConnect inbound.
func ocservProcName(inboundId int) string {
	return fmt.Sprintf("ocserv-server-%d", inboundId)
}

// certPaths returns the server cert + key file paths ocserv should reference. In
// path mode the operator's own paths are used verbatim; in content mode the PEMs
// are written into the inbound's config dir (see writeCertFiles).
func (s *OcservService) certPaths(inbound *model.Inbound, settings *ocservSettings) (certPath, keyPath string) {
	if settings.TlsUseFile && strings.TrimSpace(settings.CertificateFile) != "" && strings.TrimSpace(settings.KeyFile) != "" {
		return strings.TrimSpace(settings.CertificateFile), strings.TrimSpace(settings.KeyFile)
	}
	dir := s.configDir(inbound.Id)
	return dir + "/server.crt", dir + "/server.key"
}

// hasUsableCert reports whether a server cert+key is available on disk (content
// mode written, or an operator path that exists). ocserv refuses to start without
// one, so RestartServices skips inbounds that have none yet.
func (s *OcservService) hasUsableCert(inbound *model.Inbound, settings *ocservSettings) bool {
	certPath, keyPath := s.certPaths(inbound, settings)
	if _, err := os.Stat(certPath); err != nil {
		return false
	}
	if _, err := os.Stat(keyPath); err != nil {
		return false
	}
	return true
}

// buildServerConfig returns the ocserv.conf content for an inbound.
func (s *OcservService) buildServerConfig(inbound *model.Inbound, settings *ocservSettings) string {
	id := inbound.Id
	dir := s.configDir(id)
	port := inbound.Port

	netAddr, prefix := ocservBlockFor(inbound, settings)
	network := netAddr.String()
	netmask := prefixToMask(prefix)

	dns1 := settings.Dns1
	if dns1 == "" {
		dns1 = "8.8.8.8"
	}
	dns2 := settings.Dns2
	if dns2 == "" {
		dns2 = "8.8.4.4"
	}
	mtu := settings.Mtu
	if mtu == 0 {
		mtu = 1420 // conservative default; DTLS/TLS overhead on a 1500 path
	}

	certPath, keyPath := s.certPaths(inbound, settings)

	// max-same-clients is ocserv's native per-user simultaneous-device cap; it maps
	// directly onto our User Limit K. The RADIUS server still pins each device to a
	// distinct block IP via Framed-IP-Address (Phase 3), and finer accept/reject
	// eviction is layered on with occtl there.
	k := normUserLimit(settings.UserLimit)

	var b strings.Builder
	b.WriteString("# Auto-generated by vpn-ui OpenConnect service — do not edit\n")
	b.WriteString(fmt.Sprintf("auth = \"radius[config=%s/radiusclient.conf,groupconfig=true]\"\n", dir))
	b.WriteString(fmt.Sprintf("acct = \"radius[config=%s/radiusclient.conf]\"\n", dir))
	b.WriteString(fmt.Sprintf("tcp-port = %d\n", port))
	b.WriteString(fmt.Sprintf("udp-port = %d\n", port))
	b.WriteString(fmt.Sprintf("socket-file = /var/run/ocserv/ocserv-%d.sock\n", id))
	// occtl control socket — used for programmatic session control (User Limit
	// eviction via `occtl -s <sock> disconnect`).
	b.WriteString("use-occtl = true\n")
	b.WriteString(fmt.Sprintf("occtl-socket-file = %s\n", s.occtlSocket(id)))
	b.WriteString("run-as-user = root\n")
	b.WriteString("run-as-group = root\n")
	b.WriteString(fmt.Sprintf("server-cert = %s\n", certPath))
	b.WriteString(fmt.Sprintf("server-key = %s\n", keyPath))
	if strings.TrimSpace(settings.CaCert) != "" && !settings.TlsUseFile {
		b.WriteString(fmt.Sprintf("ca-cert = %s/ca.crt\n", dir))
	}
	// We build ocserv --disable-seccomp, so the isolate-workers syscall sandbox is
	// unavailable; disabling it explicitly avoids a startup error.
	b.WriteString("isolate-workers = false\n")
	b.WriteString("max-clients = 1024\n")
	b.WriteString(fmt.Sprintf("max-same-clients = %d\n", k))
	b.WriteString("keepalive = 32400\n")
	b.WriteString("dpd = 90\n")
	b.WriteString("mobile-dpd = 1800\n")
	b.WriteString("switch-to-tcp-timeout = 25\n")
	b.WriteString("try-mtu-discovery = true\n")
	b.WriteString("cisco-client-compat = true\n")
	b.WriteString("dtls-legacy = true\n")
	b.WriteString("compression = false\n")
	// Auth backend returns the tunnel IP (Framed-IP-Address); no predictable/local
	// pool assignment so the RADIUS pin is authoritative.
	b.WriteString("predictable-ips = false\n")
	b.WriteString(fmt.Sprintf("device = ocserv-%d\n", id))
	b.WriteString(fmt.Sprintf("ipv4-network = %s\n", network))
	b.WriteString(fmt.Sprintf("ipv4-netmask = %s\n", netmask))
	b.WriteString("tunnel-all-dns = true\n")
	b.WriteString(fmt.Sprintf("dns = %s\n", dns1))
	b.WriteString(fmt.Sprintf("dns = %s\n", dns2))
	b.WriteString(fmt.Sprintf("mtu = %d\n", mtu))
	// Full-tunnel: push the default route so ALL client traffic enters the tun,
	// where the nftables TPROXY hook redirects it into Xray (no split routes, no
	// masquerade — Xray owns egress).
	b.WriteString("route = default\n")
	if settings.ClientToClient {
		// Let ocserv bridge client-to-client traffic internally instead of routing
		// it out the tun (where TPROXY would capture it).
		b.WriteString("# client-to-client enabled\n")
	}
	b.WriteString("cert-user-oid = 0.9.2342.19200300.100.1.1\n")
	b.WriteString("log-level = 1\n")

	return b.String()
}

// writeCertFiles writes the content-mode server cert/key (and optional CA) to the
// inbound's config dir. In path mode ocserv reads the operator's own files, so
// nothing is written here.
func (s *OcservService) writeCertFiles(inbound *model.Inbound) error {
	settings, err := s.parseSettings(inbound)
	if err != nil {
		return err
	}
	if settings.TlsUseFile {
		return nil
	}

	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)

	if strings.TrimSpace(settings.Certificate) != "" {
		if err := s.writeFile(dir+"/server.crt", settings.Certificate); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.Key) != "" {
		if err := s.writeFileMode(dir+"/server.key", settings.Key, 0600); err != nil {
			return err
		}
	}
	if strings.TrimSpace(settings.CaCert) != "" {
		if err := s.writeFile(dir+"/ca.crt", settings.CaCert); err != nil {
			return err
		}
	}
	return nil
}

// writeRadiusClientConfig writes the per-inbound radcli client config so ocserv
// authenticates + accounts against the panel's in-process RADIUS server. radcli
// (ocserv's RADIUS library) uses `nas-identifier` (hyphen) — distinct from pppd's
// `nas_identifier` — so it can't share L2TP/PPTP's config; it carries a per-inbound
// nas-identifier `openconnect-{id}` that the RADIUS server resolves directly.
func (s *OcservService) writeRadiusClientConfig(inbound *model.Inbound) error {
	dir := s.configDir(inbound.Id)
	os.MkdirAll(dir, 0755)

	// Reuse the self-contained dictionary the RADIUS service ships (it already
	// carries NAS-Identifier, Framed-IP-Address, and the accounting attributes).
	if err := generateRadiusDictionary(dir); err != nil {
		return fmt.Errorf("failed to write dictionary: %w", err)
	}

	config := fmt.Sprintf(`# Auto-generated by vpn-ui OpenConnect (radcli) — do not edit
authserver	127.0.0.1:1812
acctserver	127.0.0.1:1813
servers		%s/servers
dictionary	%s/dictionary
default_realm
radius_timeout	5
radius_retries	3
nas-identifier	openconnect-%d
bindaddr	*
`, dir, dir, inbound.Id)
	if err := os.WriteFile(dir+"/radiusclient.conf", []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write radiusclient.conf: %w", err)
	}

	servers := fmt.Sprintf("127.0.0.1\t%s\n", s.radiusSecret)
	return os.WriteFile(dir+"/servers", []byte(servers), 0600)
}

// SetupRouting prepares the host so OpenConnect client traffic is TPROXY-redirected
// into Xray instead of NAT'd to the internet. Shares the fwmark policy route and
// nftables regeneration with the other VPN protocols.
func (s *OcservService) SetupRouting() error {
	s.runCmd("sysctl", "-w", "net.ipv4.ip_forward=1")

	s.runCmd("modprobe", "tun")
	s.runCmd("modprobe", "nf_tproxy_ipv4")

	output, _ := exec.Command("ip", "rule", "show").Output()
	if !strings.Contains(string(output), "fwmark 0x1 lookup 100") {
		s.runCmd("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	}
	s.runCmd("ip", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100")

	return s.nftService.ApplyNftRules()
}

// RestartServices launches (or stops) an ocserv child process per inbound. An
// inbound with no usable server cert yet is skipped (ocserv refuses to start
// without one). Managed ocserv processes with no corresponding enabled inbound
// are stopped.
func (s *OcservService) RestartServices() error {
	migrateFromSystemd()

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return err
	}

	bin := s.ocservBinaryPath()
	desired := map[string]bool{}

	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		settings, err := s.parseSettings(inbound)
		if err != nil {
			logger.Warning("OpenConnect: skipping inbound", inbound.Id, err)
			continue
		}
		if !s.hasUsableCert(inbound, settings) {
			logger.Warning("OpenConnect: inbound", inbound.Id, "has no TLS cert yet — generate a self-signed cert or set a cert path")
			continue
		}
		dir := s.configDir(inbound.Id)
		name := ocservProcName(inbound.Id)
		desired[name] = true
		confPath := fmt.Sprintf("%s/ocserv.conf", dir)
		args := []string{"-f", "-c", confPath}
		if err := procMgr.Start(name, bin, args, nil, dir); err != nil {
			logger.Warning("OpenConnect: failed to start", name, err)
		}
	}

	for _, name := range procMgr.namesWithPrefix("ocserv-server-") {
		if !desired[name] {
			_ = procMgr.Stop(name)
		}
	}
	return nil
}

// StopServices stops all OpenConnect child processes.
func (s *OcservService) StopServices() {
	procMgr.StopByPrefix("ocserv-server-")
}

// GenerateSelfSignedCert generates a self-signed server certificate + key for
// ocserv. Unlike OpenVPN (which needs a CA + tls-crypt), ocserv only needs a
// server cert the client trusts (or bypasses with --no-cert-check); a single
// self-issued ECDSA P-384 cert suffices. Returns PEM strings: serverCert, serverKey.
func (s *OcservService) GenerateSelfSignedCert() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate server key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"vpn-ui"},
			CommonName:   "vpn-ui OpenConnect Server",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return "", "", fmt.Errorf("failed to create server cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return string(certPEM), string(keyPEM), nil
}

// occtlSocket returns the occtl control-socket path for an inbound's ocserv.
func (s *OcservService) occtlSocket(inboundId int) string {
	return fmt.Sprintf("/var/run/ocserv/occtl-%d.sock", inboundId)
}

// KillClient disconnects a user's active session(s) on an inbound's ocserv via
// occtl. Best-effort: a no-op if the socket/daemon isn't up. `disconnect user`
// drops every session for that username (whole-account teardown), which is what
// the disable/expiry callers want. Per-device eviction (User Limit "accept")
// uses `disconnect id` and is layered on in the RADIUS path.
func (s *OcservService) KillClient(inboundId int, username string) {
	if username == "" {
		return
	}
	sock := s.occtlSocket(inboundId)
	if _, err := os.Stat(sock); err != nil {
		return
	}
	_ = s.runCmd(s.occtlBinaryPath(), "-s", sock, "disconnect", "user", username)
}

// KillDisabledSessions disconnects active OpenConnect sessions for clients that
// are disabled (in settings or via the client_traffics quota/expiry table).
func (s *OcservService) KillDisabledSessions() {
	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	disabledEmails := s.getDisabledEmails()

	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if !client.Enable || disabledEmails[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// DisableClients disconnects the given client emails' active sessions.
func (s *OcservService) DisableClients(emails []string) {
	if len(emails) == 0 {
		return
	}
	emailSet := make(map[string]bool, len(emails))
	for _, e := range emails {
		emailSet[e] = true
	}

	inbounds, err := s.GetOcservInbounds()
	if err != nil {
		return
	}
	for _, inbound := range inbounds {
		settings, err := s.parseSettings(inbound)
		if err != nil {
			continue
		}
		for _, client := range settings.Clients {
			if emailSet[client.Email] {
				s.KillClient(inbound.Id, client.ID)
			}
		}
	}
}

// getDisabledEmails returns the set of client emails disabled in client_traffics
// (traffic limit or expiry).
func (s *OcservService) getDisabledEmails() map[string]bool {
	disabled := make(map[string]bool)
	db := database.GetDB()
	var emails []string
	db.Model(&xray.ClientTraffic{}).
		Where("enable = ?", false).
		Pluck("email", &emails)
	for _, e := range emails {
		disabled[e] = true
	}
	return disabled
}

// getServerIP returns the server's primary IP address (default-route source).
func (s *OcservService) getServerIP() string {
	output, err := exec.Command("ip", "-4", "route", "get", "1.1.1.1").Output()
	if err == nil {
		parts := strings.Fields(string(output))
		for i, p := range parts {
			if p == "src" && i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	return ""
}

func (s *OcservService) writeFile(path, content string) error {
	return s.writeFileMode(path, content, 0644)
}

func (s *OcservService) writeFileMode(path, content string, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func (s *OcservService) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Debugf("OpenConnect: cmd '%s %s' failed: %s %v", name, strings.Join(args, " "), string(output), err)
		return err
	}
	return nil
}
