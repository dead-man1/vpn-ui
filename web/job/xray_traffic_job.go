package job

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/service/rbridge"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/valyala/fasthttp"
)

// XrayTrafficJob collects and processes traffic statistics from Xray, updating the database and optionally informing external APIs.
type XrayTrafficJob struct {
	settingService  service.SettingService
	xrayService     service.XrayService
	inboundService  service.InboundService
	outboundService service.OutboundService
	l2tpService     service.L2tpService
	pptpService     service.PptpService
	openvpnService  service.OpenVpnService
	ocservService   service.OcservService
	sstpService     service.SstpService
	ikev2Service    service.Ikev2Service
	wgcService      service.WgcService
	mtprotoService  service.MtprotoService
	nftService      service.NftService
	radiusService   *service.RadiusService
	sweeper         *rbridge.Sweeper
}

// NewXrayTrafficJob creates a new traffic collection job instance.
func NewXrayTrafficJob(rs *service.RadiusService) *XrayTrafficJob {
	j := &XrayTrafficJob{radiusService: rs}
	// Wire the shared RADIUS server into THIS job's own l2tp/pptp/openvpn service
	// structs. They are zero-value copies (not the web server's wired instances), so
	// without this their radiusService is nil and every DisableClients / KillDisabled-
	// Sessions call silently no-ops (see the `s.radiusService != nil` guards) — which
	// is why over-quota and disabled l2tp/pptp tunnels were never torn down live and
	// only got refused at the next reconnect. The secret is irrelevant to the kill
	// paths (they read the in-memory session map), so pass empty; getRadiusSecret
	// falls back to the DB if anything else needs it.
	j.l2tpService.SetRadius(rs, "")
	j.pptpService.SetRadius(rs, "")
	j.openvpnService.SetRadius(rs, "")
	j.ocservService.SetRadius(rs, "")
	j.sstpService.SetRadius(rs, "")
	j.ikev2Service.SetRadius(rs, "")
	// The rbridge Sweeper drives the non-RADIUS (sweep-reconciled) protocols each tick: it polls
	// their live tunnels, enforces quota/disable + User Limit, and writes their sessions +
	// nft accounting through the RADIUS service (the rbridge.Sink). ikev2 psk/eap-tls is the
	// first such adapter; future non-RADIUS protocols (e.g. WireGuard) register here too.
	j.sweeper = rbridge.New(rs)
	j.sweeper.Register(&j.ikev2Service)
	j.sweeper.Register(&j.wgcService)
	return j
}

// Run collects traffic statistics from Xray and updates the database, triggering restart if needed.
func (j *XrayTrafficJob) Run() {
	var traffics []*xray.Traffic
	var clientTraffics []*xray.ClientTraffic

	if j.xrayService.IsXrayRunning() {
		var err error
		traffics, clientTraffics, err = j.xrayService.GetXrayTraffic()
		if err != nil {
			traffics = nil
			clientTraffics = nil
		}
	}

	// Collect L2TP, PPTP, and OpenVPN per-client traffic from nftables counters (atomic read+reset)
	// Session maps (IP→email) come from the embedded RADIUS server
	// This runs regardless of Xray status — VPN traffic is independent
	// Non-RADIUS protocols (ikev2 psk/eap-tls, ...) authenticate locally with no RADIUS
	// round-trip, so the rbridge Sweeper reconciles their live tunnels into the session store +
	// nft counters BEFORE reading sessions below, so this tick bills their traffic and enforces
	// their quota + User Limit.
	// WireGuard: reconcile the kernel peer set to DB state FIRST (before the sweep polls),
	// so the interface holds exactly the enabled, non-disabled devices. Because a removed
	// peer cannot complete a handshake, this makes disable/quota enforcement HARD (a
	// disabled account cannot reconnect at all) and re-adds re-enabled accounts within one
	// tick — no eventual-eviction window. Cheap: a few in-process wgctrl/netlink calls.
	if err := j.wgcService.GenerateAllConfigs(); err != nil {
		logger.Debug("wgc: peer reconcile failed:", err)
	}

	if j.sweeper != nil {
		j.sweeper.Tick()
	}

	vpnSessions := map[string]map[string]string{
		"l2tp":        j.radiusService.GetSessions("l2tp"),
		"pptp":        j.radiusService.GetSessions("pptp"),
		"openvpn":     j.radiusService.GetSessions("openvpn"),
		"openconnect": j.radiusService.GetSessions("openconnect"),
		"sstp":        j.radiusService.GetSessions("sstp"),
		"ikev2":       j.radiusService.GetSessions("ikev2"),
		"wg-c":        j.radiusService.GetSessions("wg-c"),
	}
	clientTraffics = append(clientTraffics, j.nftService.CollectAndResetTraffic(vpnSessions)...)

	// MTProto bills from telemt's own per-user counters instead of the nft per-IP
	// path above. It has to: it is a userspace relay, so no client ever gets a
	// tunnel IP for a counter to be keyed on. Routing it through the nft path
	// anyway would fail SILENTLY (AddClientAccounting swallows every nft error and
	// returns nil), leaving mtproto accounts permanently online and billing zero.
	clientTraffics = append(clientTraffics, j.mtprotoService.CollectTraffic()...)

	// Level-triggered enforcement: disconnect any STILL-connected client that is no
	// longer allowed (quota/expiry hit, or disabled in settings). The edge-triggered
	// DisableClients calls below only fire on the exact tick a quota is first crossed;
	// if that one-shot kill missed, the live VPN tunnel would keep running until the
	// user reconnects (auth refuses them only then) — the reported "used their 1GB but
	// kept going" bug. This sweep re-derives the disabled set from the DB each run, so
	// it is idempotent and cheap when nothing is disabled. Runs before the early-return
	// so an idle-but-over-quota session is still torn down.
	j.l2tpService.KillDisabledSessions()
	j.pptpService.KillDisabledSessions()
	j.openvpnService.KillDisabledSessions()
	j.ocservService.KillDisabledSessions()
	j.sstpService.KillDisabledSessions()
	j.ikev2Service.KillDisabledSessions()
	// MTProto: re-renders [access.user_enabled] from client_traffics. telemt's config
	// watcher applies it and cancels the disabled accounts' live sessions itself, so
	// there is no separate kill path and no daemon restart.
	j.mtprotoService.KillDisabledSessions()

	// Skip DB update if no traffic to process
	if len(traffics) == 0 && len(clientTraffics) == 0 {
		return
	}

	err, needRestart0, l2tpDisabledEmails, pptpDisabledEmails, ovpnDisabledEmails := j.inboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add inbound traffic failed:", err)
	}
	// AddTraffic is where THIS tick's bytes land and a crossed quota flips the account
	// to disabled, so the sweep above (which ran before it) could only ever see the
	// PREVIOUS tick's verdict: an account that blew its quota kept relaying for one
	// more full interval. Re-run it here so the same tick that detects the overage
	// also ends the session, halving worst-case overshoot. Idempotent and cheap: it
	// re-renders the config and generateServerConfig now skips writing when the bytes
	// are unchanged, so a no-op tick costs a read and no reload.
	j.mtprotoService.KillDisabledSessions()
	// Enforce limits on L2TP clients (kill sessions, regenerate chap-secrets)
	if len(l2tpDisabledEmails) > 0 {
		j.l2tpService.DisableClients(l2tpDisabledEmails)
	}
	// Enforce limits on PPTP clients
	if len(pptpDisabledEmails) > 0 {
		j.pptpService.DisableClients(pptpDisabledEmails)
	}
	// Enforce limits on OpenVPN clients
	if len(ovpnDisabledEmails) > 0 {
		j.openvpnService.DisableClients(ovpnDisabledEmails)
	}
	err, needRestart1 := j.outboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add outbound traffic failed:", err)
	}
	if ExternalTrafficInformEnable, err := j.settingService.GetExternalTrafficInformEnable(); ExternalTrafficInformEnable {
		j.informTrafficToExternalAPI(traffics, clientTraffics)
	} else if err != nil {
		logger.Warning("get ExternalTrafficInformEnable failed:", err)
	}
	if needRestart0 || needRestart1 {
		j.xrayService.SetToNeedRestart()
	}

	// If no frontend client is connected, skip all WebSocket broadcasting routines,
	// including expensive DB queries for online clients and JSON marshaling.
	if !websocket.HasClients() {
		return
	}

	// Update online clients list and map
	onlineClients := j.inboundService.GetOnlineClients()
	lastOnlineMap, err := j.inboundService.GetClientsLastOnline()
	if err != nil {
		logger.Warning("get clients last online failed:", err)
		lastOnlineMap = make(map[string]int64)
	}

	// Broadcast traffic update (deltas and online stats) via WebSocket
	trafficUpdate := map[string]any{
		"traffics":       traffics,
		"clientTraffics": clientTraffics,
		"onlineClients":  onlineClients,
		"lastOnlineMap":  lastOnlineMap,
	}
	websocket.BroadcastTraffic(trafficUpdate)

	// Fetch updated inbounds from database with accumulated traffic values
	// This ensures frontend receives the actual total traffic for real-time UI refresh.
	updatedInbounds, err := j.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("get all inbounds for websocket failed:", err)
	}

	updatedOutbounds, err := j.outboundService.GetOutboundsTraffic()
	if err != nil {
		logger.Warning("get all outbounds for websocket failed:", err)
	}

	// The WebSocket hub will automatically check the payload size.
	// If it exceeds 100MB, it sends a lightweight 'invalidate' signal instead.
	if updatedInbounds != nil {
		websocket.BroadcastInbounds(updatedInbounds)
	}

	if updatedOutbounds != nil {
		websocket.BroadcastOutbounds(updatedOutbounds)
	}
}

func (j *XrayTrafficJob) informTrafficToExternalAPI(inboundTraffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) {
	informURL, err := j.settingService.GetExternalTrafficInformURI()
	if err != nil {
		logger.Warning("get ExternalTrafficInformURI failed:", err)
		return
	}
	requestBody, err := json.Marshal(map[string]any{"clientTraffics": clientTraffics, "inboundTraffics": inboundTraffics})
	if err != nil {
		logger.Warning("parse client/inbound traffic failed:", err)
		return
	}
	request := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(request)
	request.Header.SetMethod("POST")
	request.Header.SetContentType("application/json; charset=UTF-8")
	request.SetBody([]byte(requestBody))
	request.SetRequestURI(informURL)
	response := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(response)
	if err := fasthttp.Do(request, response); err != nil {
		logger.Warning("POST ExternalTrafficInformURI failed:", err)
	}
}
