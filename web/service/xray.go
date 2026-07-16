package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"go.uber.org/atomic"
)

var (
	p                 *xray.Process
	lock              sync.Mutex
	isNeedXrayRestart atomic.Bool // Indicates that restart was requested for Xray
	isManuallyStopped atomic.Bool // Indicates that Xray was stopped manually from the panel
	result            string
)

// XrayService provides business logic for Xray process management.
// It handles starting, stopping, restarting Xray, and managing its configuration.
type XrayService struct {
	inboundService InboundService
	settingService SettingService
	l2tpService    L2tpService
	pptpService    PptpService
	openvpnService OpenVpnService
	ocservService  OcservService
	sstpService    SstpService
	ikev2Service   Ikev2Service
	wgcService     WgcService
	mtprotoService MtprotoService
	xrayAPI        xray.XrayAPI
}

// IsXrayRunning checks if the Xray process is currently running.
func (s *XrayService) IsXrayRunning() bool {
	return p != nil && p.IsRunning()
}

// GetXrayErr returns the error from the Xray process, if any.
func (s *XrayService) GetXrayErr() error {
	if p == nil {
		return nil
	}

	err := p.GetErr()
	if err == nil {
		return nil
	}

	return err
}

// GetXrayResult returns the result string from the Xray process.
func (s *XrayService) GetXrayResult() string {
	if result != "" {
		return result
	}
	if s.IsXrayRunning() {
		return ""
	}
	if p == nil {
		return ""
	}

	result = p.GetResult()

	return result
}

// GetXrayVersion returns the version of the running Xray process.
func (s *XrayService) GetXrayVersion() string {
	if p == nil {
		return "Unknown"
	}
	return p.GetVersion()
}

// RemoveIndex removes an element at the specified index from a slice.
// Returns a new slice with the element removed.
func RemoveIndex(s []any, index int) []any {
	return append(s[:index], s[index+1:]...)
}

// GetXrayConfig retrieves and builds the Xray configuration from settings and inbounds.
func (s *XrayService) GetXrayConfig() (*xray.Config, error) {
	templateConfig, err := s.settingService.GetXrayConfigTemplate()
	if err != nil {
		return nil, err
	}

	xrayConfig := &xray.Config{}
	err = json.Unmarshal([]byte(templateConfig), xrayConfig)
	if err != nil {
		return nil, err
	}

	s.inboundService.AddTraffic(nil, nil)

	inbounds, err := s.inboundService.GetAllInbounds()
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		if !inbound.Enable {
			continue
		}
		// Skip L2TP/PPTP/OpenVPN/OpenConnect/SSTP/IKEv2/WireGuard/MTProto inbounds, they
		// are not native Xray protocols. The tunnel ones route through paired
		// dokodemo-door inbounds injected below; mtproto instead gets a paired socks
		// inbound it egresses THROUGH (GetSocksConfig).
		//
		// Omitting a protocol here is not a no-op: its raw settings would be handed to
		// Xray as a native inbound, Xray would reject the unknown protocol, and the
		// WHOLE core would fail to start, taking every other inbound down with it.
		if inbound.Protocol == "l2tp" || inbound.Protocol == "pptp" || inbound.Protocol == "openvpn" || inbound.Protocol == "openconnect" || inbound.Protocol == "sstp" || inbound.Protocol == "ikev2" || inbound.Protocol == "wg-c" || inbound.Protocol == "mtproto" {
			continue
		}
		// get settings clients
		settings := map[string]any{}
		json.Unmarshal([]byte(inbound.Settings), &settings)
		clients, ok := settings["clients"].([]any)
		if ok {
			// Fast O(N) lookup map for client traffic enablement
			clientStats := inbound.ClientStats
			enableMap := make(map[string]bool, len(clientStats))
			for _, clientTraffic := range clientStats {
				enableMap[clientTraffic.Email] = clientTraffic.Enable
			}

			// filter and clean clients
			var final_clients []any
			for _, client := range clients {
				c, ok := client.(map[string]any)
				if !ok {
					continue
				}

				email, _ := c["email"].(string)

				// check users active or not via stats
				if enable, exists := enableMap[email]; exists && !enable {
					logger.Infof("Remove Inbound User %s due to expiration or traffic limit", email)
					continue
				}

				// check manual disabled flag
				if manualEnable, ok := c["enable"].(bool); ok && !manualEnable {
					continue
				}

				// clear client config for additional parameters
				for key := range c {
					if key != "email" && key != "id" && key != "password" && key != "flow" && key != "method" && key != "auth" {
						delete(c, key)
					}
					if flow, ok := c["flow"].(string); ok && flow == "xtls-rprx-vision-udp443" {
						c["flow"] = "xtls-rprx-vision"
					}
				}
				final_clients = append(final_clients, any(c))
			}

			settings["clients"] = final_clients
			modifiedSettings, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return nil, err
			}

			inbound.Settings = string(modifiedSettings)
		}

		if len(inbound.StreamSettings) > 0 {
			// Unmarshal stream JSON
			var stream map[string]any
			json.Unmarshal([]byte(inbound.StreamSettings), &stream)

			// Remove the "settings" field under "tlsSettings" and "realitySettings"
			tlsSettings, ok1 := stream["tlsSettings"].(map[string]any)
			realitySettings, ok2 := stream["realitySettings"].(map[string]any)
			if ok1 || ok2 {
				if ok1 {
					delete(tlsSettings, "settings")
				} else if ok2 {
					delete(realitySettings, "settings")
				}
			}

			delete(stream, "externalProxy")

			newStream, err := json.MarshalIndent(stream, "", "  ")
			if err != nil {
				return nil, err
			}
			inbound.StreamSettings = string(newStream)
		}

		inboundConfig := inbound.GenXrayInboundConfig()
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *inboundConfig)
	}

	// Inject paired dokodemo-door inbounds for L2TP
	l2tpInbounds, _ := s.l2tpService.GetL2tpInbounds()
	for _, l2tpInbound := range l2tpInbounds {
		if !l2tpInbound.Enable {
			continue
		}
		dokodemoConfig := s.l2tpService.GetDokodemoConfig(l2tpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for PPTP
	pptpInbounds, _ := s.pptpService.GetPptpInbounds()
	for _, pptpInbound := range pptpInbounds {
		if !pptpInbound.Enable {
			continue
		}
		dokodemoConfig := s.pptpService.GetDokodemoConfig(pptpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for OpenVPN
	ovpnInbounds, _ := s.openvpnService.GetOpenVpnInbounds()
	for _, ovpnInbound := range ovpnInbounds {
		if !ovpnInbound.Enable {
			continue
		}
		dokodemoConfig := s.openvpnService.GetDokodemoConfig(ovpnInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for OpenConnect
	ocservInbounds, _ := s.ocservService.GetOcservInbounds()
	for _, ocservInbound := range ocservInbounds {
		if !ocservInbound.Enable {
			continue
		}
		dokodemoConfig := s.ocservService.GetDokodemoConfig(ocservInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for SSTP
	sstpInbounds, _ := s.sstpService.GetSstpInbounds()
	for _, sstpInbound := range sstpInbounds {
		if !sstpInbound.Enable {
			continue
		}
		dokodemoConfig := s.sstpService.GetDokodemoConfig(sstpInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for IKEv2 (one per inbound; a single shared
	// charon serves them all, but each inbound's /16 block routes to its own dokodemo).
	ikev2Inbounds, _ := s.ikev2Service.GetIkev2Inbounds()
	for _, ikev2Inbound := range ikev2Inbounds {
		if !ikev2Inbound.Enable {
			continue
		}
		dokodemoConfig := s.ikev2Service.GetDokodemoConfig(ikev2Inbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject paired dokodemo-door inbounds for WireGuard (C) (one per inbound; the kernel
	// wireguard interface decrypts, each inbound's 10.7 block routes to its own dokodemo).
	wgcInbounds, _ := s.wgcService.GetWgcInbounds()
	for _, wgcInbound := range wgcInbounds {
		if !wgcInbound.Enable {
			continue
		}
		dokodemoConfig := s.wgcService.GetDokodemoConfig(wgcInbound)
		xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *dokodemoConfig)
	}

	// Inject the loopback socks inbound each MTProto Proxy inbound egresses through.
	// This is the mtproto analogue of the dokodemo-door blocks above, but a socks
	// listener rather than TPROXY capture: telemt is a userspace relay with no tunnel
	// to intercept, so it dials OUT through Xray instead of having packets pushed in.
	// The inbound carries inbound.Tag, so operator routing rules target it like any
	// other. Returns nil when adtag is on, middle-proxy mode must egress directly,
	// because its RPC key is derived from the proxy's own egress IP AND port.
	mtprotoInbounds, _ := s.mtprotoService.GetMtprotoInbounds()
	for _, mtInbound := range mtprotoInbounds {
		if !mtInbound.Enable {
			continue
		}
		if socksConfig := s.mtprotoService.GetSocksConfig(mtInbound); socksConfig != nil {
			xrayConfig.InboundConfigs = append(xrayConfig.InboundConfigs, *socksConfig)
		}
	}

	// Translate email-based routing rules for L2TP/PPTP clients to source-IP rules.
	// Dokodemo-door doesn't support per-user identification, so we use deterministic
	// IP assignment and match on source IP instead.
	//
	// MTProto is deliberately absent from this translation: it assigns no per-client
	// IP, so a per-CLIENT rule has nothing to match on. Its routing is per-INBOUND,
	// via the socks inbound's tag above.
	s.translateVpnRoutingRules(xrayConfig)

	return xrayConfig, nil
}

// translateVpnRoutingRules rewrites routing rules so that "user" (email) matches
// for L2TP/PPTP clients are translated to "source" (IP) matches.
//
// Emails absent from the map are left as "user" rules on purpose, and two very
// different protocol families rely on that: Xray-native ones (vless/vmess), which
// match the user natively, and mtproto, whose account arrives as the socks username
// (see MtprotoService.GetSocksConfig). So an operator writes the same
// user:[email] rule for every protocol and this decides the carrier. Do NOT add
// mtproto to BuildVpnEmailToIPMap to "complete" it: a relay has no per-client IP,
// so it would translate the rule into a source match on an IP that never exists
// and the rule would silently stop matching anything.
func (s *XrayService) translateVpnRoutingRules(config *xray.Config) {
	if len(config.RouterConfig) == 0 {
		return
	}

	vpnMap := BuildVpnEmailToIPMap()
	if len(vpnMap) == 0 {
		return
	}

	var routing map[string]any
	if err := json.Unmarshal(config.RouterConfig, &routing); err != nil {
		return
	}

	rulesRaw, ok := routing["rules"].([]any)
	if !ok || len(rulesRaw) == 0 {
		return
	}

	var newRules []any
	modified := false

	for _, ruleRaw := range rulesRaw {
		rule, ok := ruleRaw.(map[string]any)
		if !ok {
			newRules = append(newRules, ruleRaw)
			continue
		}

		usersRaw, ok := rule["user"].([]any)
		if !ok || len(usersRaw) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		// Separate VPN emails from regular Xray emails
		var vpnIPs []any
		var regularEmails []any
		for _, u := range usersRaw {
			email, ok := u.(string)
			if !ok {
				regularEmails = append(regularEmails, u)
				continue
			}
			if ips, found := vpnMap[email]; found {
				for _, ip := range ips {
					vpnIPs = append(vpnIPs, ip)
				}
			} else {
				regularEmails = append(regularEmails, u)
			}
		}

		if len(vpnIPs) == 0 {
			newRules = append(newRules, rule)
			continue
		}

		modified = true

		// Create source-based rule for VPN clients (copy all fields except "user")
		vpnRule := make(map[string]any)
		for k, v := range rule {
			if k != "user" {
				vpnRule[k] = v
			}
		}
		vpnRule["source"] = vpnIPs
		newRules = append(newRules, vpnRule)

		// Keep original rule with remaining non-VPN emails
		if len(regularEmails) > 0 {
			rule["user"] = regularEmails
			newRules = append(newRules, rule)
		}
	}

	// Backstop: block any VPN tunnel source that isn't a valid account device IP.
	// nftables TPROXYs the WHOLE client /24 into Xray, and with no matching rule a
	// packet falls through to Xray's default (first) outbound — so a device holding an
	// in-/24 but out-of-block IP (an over-limit device, a failed eviction, or a keyless
	// Access-Accept fallback) would otherwise reach the internet, making the User Limit
	// cap cosmetic. We list every legitimate device IP -> the default outbound, then
	// blackhole the rest of the VPN space. Appended last, so operator per-account rules
	// still take precedence for valid IPs; only unrecognized (over-limit / leaked)
	// sources hit the blackhole. Tags are taken from the config's own outbounds so the
	// default egress is preserved and the backstop is skipped when no blackhole exists.
	defaultTag, blockTag := "direct", ""
	var obs []map[string]any
	if json.Unmarshal(config.OutboundConfigs, &obs) == nil {
		for i, ob := range obs {
			t, _ := ob["tag"].(string)
			if i == 0 && t != "" {
				defaultTag = t
			}
			if p, _ := ob["protocol"].(string); p == "blackhole" && t != "" {
				blockTag = t
			}
		}
	}
	var validIPs []any
	seen := make(map[string]bool)
	for _, ips := range vpnMap {
		for _, ip := range ips {
			if ip != "" && !seen[ip] {
				seen[ip] = true
				validIPs = append(validIPs, ip)
			}
		}
	}
	if blockTag != "" && len(validIPs) > 0 {
		newRules = append(newRules,
			map[string]any{"type": "field", "source": validIPs, "outboundTag": defaultTag},
			map[string]any{"type": "field", "source": []any{vpnAddrSpace}, "outboundTag": blockTag},
		)
		modified = true
	}

	if !modified {
		return
	}

	routing["rules"] = newRules
	if data, err := json.Marshal(routing); err == nil {
		config.RouterConfig = data
	}
}

// GetXrayTraffic fetches the current traffic statistics from the running Xray process.
func (s *XrayService) GetXrayTraffic() ([]*xray.Traffic, []*xray.ClientTraffic, error) {
	if !s.IsXrayRunning() {
		err := errors.New("xray is not running")
		logger.Debug("Attempted to fetch Xray traffic, but Xray is not running:", err)
		return nil, nil, err
	}
	apiPort := p.GetAPIPort()
	if err := s.xrayAPI.Init(apiPort); err != nil {
		logger.Debug("Failed to initialize Xray API:", err)
		return nil, nil, err
	}
	defer s.xrayAPI.Close()

	traffic, clientTraffic, err := s.xrayAPI.GetTraffic(true)
	if err != nil {
		logger.Debug("Failed to fetch Xray traffic:", err)
		return nil, nil, err
	}
	return traffic, clientTraffic, nil
}

// RestartXray restarts the Xray process, optionally forcing a restart even if config unchanged.
func (s *XrayService) RestartXray(isForce bool) error {
	lock.Lock()
	defer lock.Unlock()
	logger.Debug("restart Xray, force:", isForce)
	isManuallyStopped.Store(false)

	xrayConfig, err := s.GetXrayConfig()
	if err != nil {
		return err
	}

	if s.IsXrayRunning() {
		if !isForce && p.GetConfig().Equals(xrayConfig) && !isNeedXrayRestart.Load() {
			logger.Debug("It does not need to restart Xray")
			return nil
		}
		p.Stop()
	}

	p = xray.NewProcess(xrayConfig)
	result = ""
	err = p.Start()
	if err != nil {
		return err
	}

	return nil
}

// StopXray stops the running Xray process.
func (s *XrayService) StopXray() error {
	lock.Lock()
	defer lock.Unlock()
	isManuallyStopped.Store(true)
	logger.Debug("Attempting to stop Xray...")
	if s.IsXrayRunning() {
		return p.Stop()
	}
	return errors.New("xray is not running")
}

// ReapOrphanXray kills a stray Xray left by a previous panel instance that never
// stopped it — most importantly a self-update re-exec: syscall.Exec keeps the SAME
// PID, so the old Xray survives as an orphaned child still holding 127.0.0.1:62790
// (the API/dokodemo port) and every inbound port. The re-exec'd panel starts with
// p == nil, so RestartXray's stop-guard is a no-op and it just spawns a SECOND Xray
// that fails to bind ("address already in use") — the health job then reports the
// error state in a permanent loop. Mirrors procmgr's daemon reap (procmgr.go).
//
// MUST be called at startup BEFORE the first RestartXray, while p is still nil, so it
// can only ever match an orphan — never the Xray we manage.
func (s *XrayService) ReapOrphanXray() {
	if s.IsXrayRunning() {
		return
	}
	// Our working directory. Xray inherits the panel's cwd, so we match orphaned xray
	// processes by cwd == ours: a coexisting upstream x-ui's xray runs from a different
	// dir and is never touched. We deliberately do NOT match /proc/<pid>/exe — the core
	// bundle re-extracts bin/xray on startup (fresh inode), so an orphan's exe reads
	// "…(deleted)" and would no longer compare equal; cwd (and the cmdline) are stable.
	myCwd, err := os.Getwd()
	if err != nil {
		return
	}
	if resolved, err := filepath.EvalSymlinks(myCwd); err == nil {
		myCwd = resolved
	}
	self := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		// Only xray processes (the bundled core binary name appears in the cmdline)...
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !strings.Contains(string(cmdline), "xray-linux-amd64") {
			continue
		}
		// ...that were launched from OUR working directory.
		cwd, err := os.Readlink("/proc/" + e.Name() + "/cwd")
		if err != nil || cwd != myCwd {
			continue
		}
		logger.Warning("reaping orphaned Xray holding its ports before start (e.g. from a self-update re-exec): pid", pid)
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Kill()
		}
	}
}

// SetToNeedRestart marks that Xray needs to be restarted.
func (s *XrayService) SetToNeedRestart() {
	isNeedXrayRestart.Store(true)
}

// IsNeedRestartAndSetFalse checks if restart is needed and resets the flag to false.
func (s *XrayService) IsNeedRestartAndSetFalse() bool {
	return isNeedXrayRestart.CompareAndSwap(true, false)
}

// DidXrayCrash checks if Xray crashed by verifying it's not running and wasn't manually stopped.
func (s *XrayService) DidXrayCrash() bool {
	return !s.IsXrayRunning() && !isManuallyStopped.Load()
}
