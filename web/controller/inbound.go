package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"

	"github.com/gin-gonic/gin"
)

// InboundController handles HTTP requests related to Xray inbounds management.
type InboundController struct {
	inboundService service.InboundService
	xrayService    service.XrayService
	l2tpService    service.L2tpService
	pptpService    service.PptpService
	openvpnService service.OpenVpnService
	ocservService  service.OcservService
	sstpService    service.SstpService
	ikev2Service   service.Ikev2Service
	wgcService     service.WgcService
	mtprotoService service.MtprotoService
}

// NewInboundController creates a new InboundController and sets up its routes.
func NewInboundController(g *gin.RouterGroup) *InboundController {
	a := &InboundController{}
	a.initRouter(g)
	return a
}

// initRouter initializes the routes for inbound-related operations.
func (a *InboundController) initRouter(g *gin.RouterGroup) {

	g.GET("/list", a.getInbounds)
	g.GET("/get/:id", a.getInbound)
	g.GET("/getClientTraffics/:email", a.getClientTraffics)
	g.GET("/getClientTrafficsById/:id", a.getClientTrafficsById)

	g.POST("/add", a.addInbound)
	g.POST("/del/:id", a.delInbound)
	g.POST("/update/:id", a.updateInbound)
	g.POST("/clientIps/:email", a.getClientIps)
	g.POST("/clearClientIps/:email", a.clearClientIps)
	g.POST("/addClient", a.addInboundClient)
	g.POST("/:id/copyClients", a.copyInboundClients)
	g.POST("/:id/delClient/:clientId", a.delInboundClient)
	g.POST("/updateClient/:clientId", a.updateInboundClient)
	g.POST("/bulkUpdateClients", a.bulkUpdateClients)
	g.POST("/:id/resetClientTraffic/:email", a.resetClientTraffic)
	g.POST("/resetAllTraffics", a.resetAllTraffics)
	g.POST("/resetAllClientTraffics/:id", a.resetAllClientTraffics)
	g.POST("/delDepletedClients/:id", a.delDepletedClients)
	g.POST("/import", a.importInbound)
	g.POST("/onlines", a.onlines)
	g.POST("/lastOnline", a.lastOnline)
	g.POST("/updateClientTraffic/:email", a.updateClientTraffic)
	g.POST("/:id/delClientByEmail/:email", a.delInboundClientByEmail)
	g.GET("/:id/ovpn/:proto", a.downloadOvpn)
	g.POST("/:id/generate-openvpn-certs", a.generateOpenVpnCerts)
	// id-less variant so certs can be generated for a not-yet-saved inbound
	g.POST("/generate-openvpn-certs", a.generateOpenVpnCerts)
	g.POST("/:id/generate-ocserv-cert", a.generateOcservCert)
	g.POST("/generate-ocserv-cert", a.generateOcservCert)
	g.POST("/:id/generate-sstp-cert", a.generateSstpCert)
	g.POST("/generate-sstp-cert", a.generateSstpCert)
	g.POST("/:id/generate-ikev2-cert", a.generateIkev2Cert)
	g.POST("/generate-ikev2-cert", a.generateIkev2Cert)
	g.POST("/check-ikev2-cert", a.checkIkev2Cert)
	// WireGuard (C): render a client's per-device .conf(s) (keys are server-minted).
	g.GET("/:id/wgc-configs", a.getWgcConfigs)
}

// onL2tpChanged regenerates L2TP configs and restarts services when an L2TP inbound is modified.
func (a *InboundController) onL2tpChanged()       { a.l2tpChanged(false) }
func (a *InboundController) onL2tpClientChanged() { a.l2tpChanged(true) }
func (a *InboundController) l2tpChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("l2tp")
	if err := a.l2tpService.GenerateAllConfigs(); err != nil {
		logger.Warning("L2TP: config generation failed:", err)
	}
	if err := a.l2tpService.SetupAllTproxy(); err != nil {
		logger.Warning("L2TP: TPROXY setup failed:", err)
	}
	// A client-only change (add/edit a client, reset traffic) needs no daemon
	// restart: the in-binary RADIUS reads clients live from the DB and no per-client
	// data lives in the xl2tpd config, so a restart would only drop connected
	// tunnels. Restart for inbound-level changes, or when the pool auto-expanded.
	if !clientOnly || expanded {
		if err := a.l2tpService.RestartServices(); err != nil {
			logger.Warning("L2TP: service restart failed:", err)
		}
		// Drop cached per-device IP assignments so a changed User Limit / range /
		// strategy takes effect on reconnect. Skipped on client-only changes so the
		// idempotent-redial cache isn't cleared mid-session.
		service.ResetAllocations("l2tp")
	}
	a.l2tpService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onPptpChanged regenerates PPTP configs and restarts services when a PPTP inbound is modified.
func (a *InboundController) onPptpChanged()       { a.pptpChanged(false) }
func (a *InboundController) onPptpClientChanged() { a.pptpChanged(true) }
func (a *InboundController) pptpChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("pptp")
	if err := a.pptpService.GenerateAllConfigs(); err != nil {
		logger.Warning("PPTP: config generation failed:", err)
	}
	if err := a.pptpService.SetupAllTproxy(); err != nil {
		logger.Warning("PPTP: TPROXY setup failed:", err)
	}
	// Client-only changes don't restart pptpd (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := a.pptpService.RestartServices(); err != nil {
			logger.Warning("PPTP: service restart failed:", err)
		}
		service.ResetAllocations("pptp")
	}
	a.pptpService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onOpenVpnChanged regenerates OpenVPN configs and restarts services when an OpenVPN inbound is modified.
func (a *InboundController) onOpenVpnChanged()       { a.openVpnChanged(false) }
func (a *InboundController) onOpenVpnClientChanged() { a.openVpnChanged(true) }
func (a *InboundController) openVpnChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("openvpn")
	// Keep live per-device leases on a client-only change (unless the pool expanded,
	// which needs a full regenerate + restart) so connected devices keep their IPs.
	preserveLeases := clientOnly && !expanded
	if err := a.openvpnService.GenerateAllConfigs(preserveLeases); err != nil {
		logger.Warning("OpenVPN: config generation failed:", err)
	}
	if err := a.openvpnService.SetupRouting(); err != nil {
		logger.Warning("OpenVPN: routing setup failed:", err)
	}
	// Adding/editing a client writes its client-config-dir block file without a
	// restart; the running server reads it on the client's next connect. Restart only
	// for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := a.openvpnService.RestartServices(); err != nil {
			logger.Warning("OpenVPN: service restart failed:", err)
		}
	}
	a.openvpnService.KillDisabledSessions()
	// OpenVPN routes through Xray via dokodemo-door, so Xray routing must refresh.
	a.xrayService.SetToNeedRestart()
}

// onOcservChanged regenerates OpenConnect configs and restarts services when an
// OpenConnect inbound is modified.
func (a *InboundController) onOcservChanged()       { a.ocservChanged(false) }
func (a *InboundController) onOcservClientChanged() { a.ocservChanged(true) }
func (a *InboundController) ocservChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("openconnect")
	if err := a.ocservService.GenerateAllConfigs(); err != nil {
		logger.Warning("OpenConnect: config generation failed:", err)
	}
	if err := a.ocservService.SetupRouting(); err != nil {
		logger.Warning("OpenConnect: routing setup failed:", err)
	}
	// Client-only changes don't restart ocserv (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := a.ocservService.RestartServices(); err != nil {
			logger.Warning("OpenConnect: service restart failed:", err)
		}
		service.ResetAllocations("openconnect")
	}
	a.ocservService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onSstpChanged regenerates SSTP (accel-ppp) configs and restarts services when an
// SSTP inbound is modified. Mirrors onOcservChanged: SSTP is a per-inbound native
// daemon that routes through Xray via dokodemo-door.
func (a *InboundController) onSstpChanged()       { a.sstpChanged(false) }
func (a *InboundController) onSstpClientChanged() { a.sstpChanged(true) }
func (a *InboundController) sstpChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("sstp")
	if err := a.sstpService.GenerateAllConfigs(); err != nil {
		logger.Warning("SSTP: config generation failed:", err)
	}
	if err := a.sstpService.SetupRouting(); err != nil {
		logger.Warning("SSTP: routing setup failed:", err)
	}
	// Client-only changes don't restart accel-ppp (auth is live via RADIUS) — see
	// l2tpChanged. Restart for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		if err := a.sstpService.RestartServices(); err != nil {
			logger.Warning("SSTP: service restart failed:", err)
		}
		service.ResetAllocations("sstp")
	}
	a.sstpService.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onIkev2Changed regenerates strongSwan config and reloads the shared charon when an
// IKEv2 inbound is modified. Like onSstpChanged/onOcservChanged, IKEv2 routes through
// Xray via dokodemo-door; unlike them there is ONE shared charon for all inbounds.
func (a *InboundController) onIkev2Changed()       { a.ikev2Changed(false) }
func (a *InboundController) onIkev2ClientChanged() { a.ikev2Changed(true) }
func (a *InboundController) ikev2Changed(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("ikev2")
	if err := a.ikev2Service.GenerateAllConfigs(); err != nil {
		logger.Warning("IKEv2: config generation failed:", err)
	}
	if err := a.ikev2Service.SetupRouting(); err != nil {
		logger.Warning("IKEv2: routing setup failed:", err)
	}
	// charon hot-reloads via swanctl --load-all (no tunnel drop) and a new client's
	// conn/pool must be (re)loaded, so always reload — this never disconnects anyone.
	if err := a.ikev2Service.RestartServices(); err != nil {
		logger.Warning("IKEv2: service restart failed:", err)
	}
	// Only drop the IP-allocation cache for inbound-level changes or a pool expansion.
	if !clientOnly || expanded {
		service.ResetAllocations("ikev2")
	}
	a.ikev2Service.KillDisabledSessions()
	a.xrayService.SetToNeedRestart()
}

// onMtprotoChanged regenerates the telemt config when an MTProto inbound is modified.
//
// Unlike its siblings there is no addressing to expand (no tunnel, so no 10.x pool,
// no AutoExpandVpnRanges/ResetAllocations) and no routing to install (egress reaches
// Xray through the paired socks inbound, not nftables).
//
// Client-only changes do NOT restart telemt: it watches its config file with inotify
// and applies [access.*] edits live, cancelling only the affected accounts' sessions.
// Inbound-level changes (port, modes, ad tag, upstream) are restart-only, because
// they live in sections telemt reads once at startup.
func (a *InboundController) onMtprotoChanged()       { a.mtprotoChanged(false) }
func (a *InboundController) onMtprotoClientChanged() { a.mtprotoChanged(true) }
func (a *InboundController) mtprotoChanged(clientOnly bool) {
	if err := a.mtprotoService.GenerateAllConfigs(); err != nil {
		logger.Warning("MTProto: config generation failed:", err)
	}
	if !clientOnly {
		if err := a.mtprotoService.RestartServices(); err != nil {
			logger.Warning("MTProto: service restart failed:", err)
		}
	}
	a.mtprotoService.KillDisabledSessions()
	// The paired socks inbound (and thus this inbound's routing tag) is built from
	// the mtproto settings, so Xray must pick the change up.
	a.xrayService.SetToNeedRestart()
}

// onWgcChanged reconciles WireGuard (C) keys + the kernel interface peer set when a
// wgc inbound is modified. Like IKEv2 it routes through Xray via dokodemo-door, but
// there is NO daemon: each inbound is a kernel wgc<id> interface driven by wgctrl.
func (a *InboundController) onWgcChanged()       { a.wgcChanged(false) }
func (a *InboundController) onWgcClientChanged() { a.wgcChanged(true) }
func (a *InboundController) wgcChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("wg-c")
	// Mint any missing server/device keypairs (sized to each account's User Limit K) and
	// persist them, so GenerateAllConfigs can materialize the peers.
	a.wgcService.ReconcileAllKeys()
	if err := a.wgcService.GenerateAllConfigs(); err != nil {
		logger.Warning("WireGuard: config generation failed:", err)
	}
	if err := a.wgcService.SetupRouting(); err != nil {
		logger.Warning("WireGuard: routing setup failed:", err)
	}
	_ = expanded
	a.xrayService.SetToNeedRestart()
}

type CopyInboundClientsRequest struct {
	SourceInboundID int      `form:"sourceInboundId" json:"sourceInboundId"`
	ClientEmails    []string `form:"clientEmails" json:"clientEmails"`
	Flow            string   `form:"flow" json:"flow"`
}

// getInbounds retrieves the list of inbounds for the logged-in user.
func (a *InboundController) getInbounds(c *gin.Context) {
	user := session.GetLoginUser(c)
	inbounds, err := a.inboundService.GetInbounds(user.Id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, inbounds, nil)
}

// getInbound retrieves a specific inbound by its ID.
func (a *InboundController) getInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "get"), err)
		return
	}
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, inbound, nil)
}

// getClientTraffics retrieves client traffic information by email.
func (a *InboundController) getClientTraffics(c *gin.Context) {
	email := c.Param("email")
	clientTraffics, err := a.inboundService.GetClientTrafficByEmail(email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.trafficGetError"), err)
		return
	}
	jsonObj(c, clientTraffics, nil)
}

// getClientTrafficsById retrieves client traffic information by inbound ID.
func (a *InboundController) getClientTrafficsById(c *gin.Context) {
	id := c.Param("id")
	clientTraffics, err := a.inboundService.GetClientTrafficByID(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.trafficGetError"), err)
		return
	}
	jsonObj(c, clientTraffics, nil)
}

// addInbound creates a new inbound configuration.
func (a *InboundController) addInbound(c *gin.Context) {
	inbound := &model.Inbound{}
	err := c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), err)
		return
	}

	// VPN protocols (L2TP/PPTP/OpenVPN) require the host backend to be provisioned
	// first (kernel modules, daemons, IPsec). Block creation with a clear message
	// until the operator runs setup from Core Settings. The UI guards this too;
	// this is defense-in-depth against a direct API call.
	if inbound.Protocol == model.L2TP || inbound.Protocol == model.PPTP || inbound.Protocol == model.OPENVPN || inbound.Protocol == model.OPENCONNECT || inbound.Protocol == model.SSTP || inbound.Protocol == model.IKEV2 {
		var coreService service.CoreService
		if !coreService.IsProvisioned() {
			pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.toasts.setupRequired"))
			return
		}
		// Provisioned, but this protocol was added after the last setup run (an
		// upgrade that introduced a new protocol) — its host prerequisites aren't
		// in place yet, so require a re-run of setup for it specifically.
		if coreService.ProtocolNeedsSetup(string(inbound.Protocol)) {
			pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.toasts.setupRequiredForProtocol"))
			return
		}
	}

	user := session.GetLoginUser(c)
	inbound.UserId = user.Id
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		inbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	} else {
		inbound.Tag = fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
	}

	// Assign/validate VPN client IP ranges (no-op for non-VPN protocols). A
	// user-supplied range overlapping another inbound is rejected here.
	if err := service.NormalizeVpnRanges(inbound, 0); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	inbound, needRestart, err := a.inboundService.AddInbound(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), inbound, nil)
	if inbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if inbound.Protocol == model.OPENCONNECT {
		a.onOcservChanged()
	} else if inbound.Protocol == model.SSTP {
		a.onSstpChanged()
	} else if inbound.Protocol == model.IKEV2 {
		a.onIkev2Changed()
	} else if inbound.Protocol == model.WGC {
		a.onWgcChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// delInbound deletes an inbound configuration by its ID.
func (a *InboundController) delInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundDeleteSuccess"), err)
		return
	}
	// Check if this is an L2TP/PPTP/OpenVPN inbound before deletion
	oldInbound, _ := a.inboundService.GetInbound(id)
	isL2tp := oldInbound != nil && oldInbound.Protocol == model.L2TP
	isPptp := oldInbound != nil && oldInbound.Protocol == model.PPTP
	isOpenVpn := oldInbound != nil && oldInbound.Protocol == model.OPENVPN
	isOcserv := oldInbound != nil && oldInbound.Protocol == model.OPENCONNECT
	isSstp := oldInbound != nil && oldInbound.Protocol == model.SSTP
	needRestart, err := a.inboundService.DelInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundDeleteSuccess"), id, nil)
	if isL2tp {
		a.onL2tpChanged()
	} else if isPptp {
		a.onPptpChanged()
	} else if isOpenVpn {
		a.onOpenVpnChanged()
	} else if isOcserv {
		a.onOcservChanged()
	} else if isSstp {
		a.onSstpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.IKEV2 {
		a.onIkev2Changed()
	} else if oldInbound != nil && oldInbound.Protocol == model.WGC {
		a.onWgcChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// updateInbound updates an existing inbound configuration.
func (a *InboundController) updateInbound(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	inbound := &model.Inbound{
		Id: id,
	}
	err = c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	// Assign/validate VPN client IP ranges (no-op for non-VPN protocols),
	// excluding this inbound so its own ranges aren't seen as overlaps.
	if err := service.NormalizeVpnRanges(inbound, id); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	inbound, needRestart, err := a.inboundService.UpdateInbound(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), inbound, nil)
	if inbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if inbound.Protocol == model.OPENCONNECT {
		a.onOcservChanged()
	} else if inbound.Protocol == model.SSTP {
		a.onSstpChanged()
	} else if inbound.Protocol == model.IKEV2 {
		a.onIkev2Changed()
	} else if inbound.Protocol == model.WGC {
		a.onWgcChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInbounds(user.Id)
	websocket.BroadcastInbounds(inbounds)
}

// getClientIps retrieves the IP addresses associated with a client by email.
func (a *InboundController) getClientIps(c *gin.Context) {
	email := c.Param("email")

	ips, err := a.inboundService.GetInboundClientIps(email)
	if err != nil || ips == "" {
		jsonObj(c, "No IP Record", nil)
		return
	}

	// Prefer returning a normalized string list for consistent UI rendering
	type ipWithTimestamp struct {
		IP        string `json:"ip"`
		Timestamp int64  `json:"timestamp"`
	}

	var ipsWithTime []ipWithTimestamp
	if err := json.Unmarshal([]byte(ips), &ipsWithTime); err == nil && len(ipsWithTime) > 0 {
		formatted := make([]string, 0, len(ipsWithTime))
		for _, item := range ipsWithTime {
			if item.IP == "" {
				continue
			}
			if item.Timestamp > 0 {
				ts := time.Unix(item.Timestamp, 0).Local().Format("2006-01-02 15:04:05")
				formatted = append(formatted, fmt.Sprintf("%s (%s)", item.IP, ts))
				continue
			}
			formatted = append(formatted, item.IP)
		}
		jsonObj(c, formatted, nil)
		return
	}

	var oldIps []string
	if err := json.Unmarshal([]byte(ips), &oldIps); err == nil && len(oldIps) > 0 {
		jsonObj(c, oldIps, nil)
		return
	}

	// If parsing fails, return as string
	jsonObj(c, ips, nil)
}

// clearClientIps clears the IP addresses for a client by email.
func (a *InboundController) clearClientIps(c *gin.Context) {
	email := c.Param("email")

	err := a.inboundService.ClearClientIps(email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.updateSuccess"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.logCleanSuccess"), nil)
}

// addInboundClient adds a new client to an existing inbound.
func (a *InboundController) addInboundClient(c *gin.Context) {
	data := &model.Inbound{}
	err := c.ShouldBind(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	needRestart, err := a.inboundService.AddInboundClient(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientAddSuccess"), nil)

	// The request body may not include protocol, so look it up from the DB.
	if data.Protocol == "" {
		if dbInbound, err := a.inboundService.GetInbound(data.Id); err == nil {
			data.Protocol = dbInbound.Protocol
		}
	}

	if data.Protocol == model.L2TP {
		a.onL2tpClientChanged()
	} else if data.Protocol == model.PPTP {
		a.onPptpClientChanged()
	} else if data.Protocol == model.OPENVPN {
		a.onOpenVpnClientChanged()
	} else if data.Protocol == model.OPENCONNECT {
		a.onOcservClientChanged()
	} else if data.Protocol == model.SSTP {
		a.onSstpClientChanged()
	} else if data.Protocol == model.IKEV2 {
		a.onIkev2ClientChanged()
	} else if data.Protocol == model.WGC {
		a.onWgcClientChanged()
	} else if data.Protocol == model.MTPROTO {
		a.onMtprotoClientChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// copyInboundClients copies clients from source inbound to target inbound.
func (a *InboundController) copyInboundClients(c *gin.Context) {
	targetID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	req := &CopyInboundClientsRequest{}
	err = c.ShouldBind(req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	if req.SourceInboundID <= 0 {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), fmt.Errorf("invalid source inbound id"))
		return
	}

	result, needRestart, err := a.inboundService.CopyInboundClients(targetID, req.SourceInboundID, req.ClientEmails, req.Flow)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// delInboundClient deletes a client from an inbound by inbound ID and client ID.
func (a *InboundController) delInboundClient(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	clientId := c.Param("clientId")

	oldInbound, _ := a.inboundService.GetInbound(id)
	needRestart, err := a.inboundService.DelInboundClient(id, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientDeleteSuccess"), nil)
	if oldInbound != nil && oldInbound.Protocol == model.L2TP {
		a.onL2tpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.PPTP {
		a.onPptpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.OPENVPN {
		a.onOpenVpnChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.OPENCONNECT {
		a.onOcservChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.SSTP {
		a.onSstpChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.IKEV2 {
		a.onIkev2Changed()
	} else if oldInbound != nil && oldInbound.Protocol == model.WGC {
		a.onWgcChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// updateInboundClient updates a client's configuration in an inbound.
func (a *InboundController) updateInboundClient(c *gin.Context) {
	clientId := c.Param("clientId")

	inbound := &model.Inbound{}
	err := c.ShouldBind(inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	needRestart, err := a.inboundService.UpdateInboundClient(inbound, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientUpdateSuccess"), nil)

	// The request body may not include protocol, so look it up from the DB.
	if inbound.Protocol == "" {
		if dbInbound, err := a.inboundService.GetInbound(inbound.Id); err == nil {
			inbound.Protocol = dbInbound.Protocol
		}
	}

	if inbound.Protocol == model.L2TP {
		a.onL2tpClientChanged()
	} else if inbound.Protocol == model.PPTP {
		a.onPptpClientChanged()
	} else if inbound.Protocol == model.OPENVPN {
		a.onOpenVpnClientChanged()
	} else if inbound.Protocol == model.OPENCONNECT {
		a.onOcservClientChanged()
	} else if inbound.Protocol == model.SSTP {
		a.onSstpClientChanged()
	} else if inbound.Protocol == model.IKEV2 {
		a.onIkev2ClientChanged()
	} else if inbound.Protocol == model.WGC {
		a.onWgcClientChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoClientChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// bulkUpdateClients applies one operation (add/subtract days or traffic, enable,
// disable) to many selected clients at once, then regenerates the touched subsystems
// once each. The payload arrives as a JSON string in the form field "data" (the panel
// axios interceptor form-encodes bodies).
func (a *InboundController) bulkUpdateClients(c *gin.Context) {
	var body struct {
		Data string `form:"data" json:"data"`
	}
	if err := c.ShouldBind(&body); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	var req service.BulkClientUpdateRequest
	if err := json.Unmarshal([]byte(body.Data), &req); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	result, touched, err := a.inboundService.BulkUpdateClients(req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, result, nil)

	xrayRestart := false
	for proto := range touched {
		switch proto {
		case string(model.L2TP):
			a.onL2tpClientChanged()
		case string(model.PPTP):
			a.onPptpClientChanged()
		case string(model.OPENVPN):
			a.onOpenVpnClientChanged()
		case string(model.OPENCONNECT):
			a.onOcservClientChanged()
		case string(model.SSTP):
			a.onSstpClientChanged()
		case string(model.IKEV2):
			a.onIkev2ClientChanged()
		case string(model.WGC):
			a.onWgcClientChanged()
		case string(model.MTPROTO):
			a.onMtprotoClientChanged()
		default:
			xrayRestart = true
		}
	}
	if xrayRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// resetClientTraffic resets the traffic counter for a specific client in an inbound.
func (a *InboundController) resetClientTraffic(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	email := c.Param("email")

	needRestart, err := a.inboundService.ResetClientTraffic(id, email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetInboundClientTrafficSuccess"), nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	a.onL2tpClientChanged()
	a.onPptpClientChanged()
	a.onOpenVpnClientChanged()
	a.onOcservClientChanged()
	a.onSstpClientChanged()
	a.onIkev2ClientChanged()
	a.onWgcClientChanged()
	a.onMtprotoClientChanged()
}

// resetAllTraffics resets all traffic counters across all inbounds.
func (a *InboundController) resetAllTraffics(c *gin.Context) {
	err := a.inboundService.ResetAllTraffics()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	} else {
		a.xrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetAllTrafficSuccess"), nil)
	a.onL2tpClientChanged()
	a.onPptpClientChanged()
	a.onOpenVpnClientChanged()
	a.onOcservClientChanged()
	a.onSstpClientChanged()
	a.onIkev2ClientChanged()
	a.onWgcClientChanged()
	a.onMtprotoClientChanged()
}

// resetAllClientTraffics resets traffic counters for all clients in a specific inbound.
func (a *InboundController) resetAllClientTraffics(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	err = a.inboundService.ResetAllClientTraffics(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	} else {
		a.xrayService.SetToNeedRestart()
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.resetAllClientTrafficSuccess"), nil)
	a.onL2tpClientChanged()
	a.onPptpClientChanged()
	a.onOpenVpnClientChanged()
	a.onOcservClientChanged()
	a.onSstpClientChanged()
	a.onIkev2ClientChanged()
	a.onWgcClientChanged()
	a.onMtprotoClientChanged()
}

// importInbound imports an inbound configuration from provided data.
func (a *InboundController) importInbound(c *gin.Context) {
	inbound := &model.Inbound{}
	err := json.Unmarshal([]byte(c.PostForm("data")), inbound)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	user := session.GetLoginUser(c)
	inbound.Id = 0
	inbound.UserId = user.Id
	if inbound.Listen == "" || inbound.Listen == "0.0.0.0" || inbound.Listen == "::" || inbound.Listen == "::0" {
		inbound.Tag = fmt.Sprintf("inbound-%v", inbound.Port)
	} else {
		inbound.Tag = fmt.Sprintf("inbound-%v:%v", inbound.Listen, inbound.Port)
	}

	for index := range inbound.ClientStats {
		inbound.ClientStats[index].Id = 0
		inbound.ClientStats[index].Enable = true
	}

	needRestart := false
	inbound, needRestart, err = a.inboundService.AddInbound(inbound)
	jsonMsgObj(c, I18nWeb(c, "pages.inbounds.toasts.inboundCreateSuccess"), inbound, err)
	if err == nil && needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// delDepletedClients deletes clients in an inbound who have exhausted their traffic limits.
func (a *InboundController) delDepletedClients(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	err = a.inboundService.DelDepletedClients(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.delDepletedClientsSuccess"), nil)
}

// onlines retrieves the list of currently online clients.
func (a *InboundController) onlines(c *gin.Context) {
	jsonObj(c, a.inboundService.GetOnlineClients(), nil)
}

// lastOnline retrieves the last online timestamps for clients.
func (a *InboundController) lastOnline(c *gin.Context) {
	data, err := a.inboundService.GetClientsLastOnline()
	jsonObj(c, data, err)
}

// updateClientTraffic updates the traffic statistics for a client by email.
func (a *InboundController) updateClientTraffic(c *gin.Context) {
	email := c.Param("email")

	// Define the request structure for traffic update
	type TrafficUpdateRequest struct {
		Upload   int64 `json:"upload"`
		Download int64 `json:"download"`
	}

	var request TrafficUpdateRequest
	err := c.ShouldBindJSON(&request)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}

	err = a.inboundService.UpdateClientTrafficByEmail(email, request.Upload, request.Download)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundClientUpdateSuccess"), nil)
}

// downloadOvpn generates and returns an .ovpn client config file.
func (a *InboundController) downloadOvpn(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	proto := c.Param("proto") // "udp" or "tcp"
	if proto != "udp" && proto != "tcp" {
		jsonMsg(c, "Invalid protocol, must be udp or tcp", nil)
		return
	}

	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}

	content, err := a.openvpnService.GenerateClientConfig(inbound, proto, browserHost(c))
	if err != nil {
		jsonMsg(c, "Failed to generate client config", err)
		return
	}

	filename := fmt.Sprintf("client-%s.ovpn", proto)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Data(200, "application/x-openvpn-profile", []byte(content))
}

// generateOpenVpnCerts generates a self-signed CA, server cert, and tls-crypt
// key for OpenVPN. Certificate generation does not need a saved inbound — the
// material is returned to the caller. When called with a valid inbound id (the
// edit case) the certs are also persisted to that inbound and applied; for a
// new (unsaved) inbound the frontend stores them in the form and the normal
// "Add inbound" save persists + applies them.
func (a *InboundController) generateOpenVpnCerts(c *gin.Context) {
	caCert, caKey, serverCert, serverKey, tlsCrypt, err := a.openvpnService.GenerateSelfSignedCA()
	if err != nil {
		jsonMsg(c, "Failed to generate certificates", err)
		return
	}

	// If editing an existing inbound, persist the certs to it and apply them.
	if id, err := strconv.Atoi(c.Param("id")); err == nil && id > 0 {
		inbound, err := a.inboundService.GetInbound(id)
		if err != nil {
			jsonMsg(c, "Inbound not found", err)
			return
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			jsonMsg(c, "Failed to parse settings", err)
			return
		}
		settings["caCert"] = caCert
		settings["caKey"] = caKey
		settings["serverCert"] = serverCert
		settings["serverKey"] = serverKey
		settings["tlsCrypt"] = tlsCrypt

		settingsJSON, _ := json.Marshal(settings)
		inbound.Settings = string(settingsJSON)
		if _, _, err := a.inboundService.UpdateInbound(inbound); err != nil {
			jsonMsg(c, "Failed to save certificates", err)
			return
		}
		a.onOpenVpnChanged()
	}

	jsonObj(c, map[string]string{
		"caCert":     caCert,
		"caKey":      caKey,
		"serverCert": serverCert,
		"serverKey":  serverKey,
		"tlsCrypt":   tlsCrypt,
	}, nil)
}

// generateOcservCert generates a self-signed server certificate + key for
// OpenConnect (ocserv). Like generateOpenVpnCerts it works with or without a
// saved inbound: with a valid id the material is persisted to the inbound (content
// mode) and applied; otherwise it is returned for the frontend to store in the
// form until the inbound is saved.
func (a *InboundController) generateOcservCert(c *gin.Context) {
	serverCert, serverKey, err := a.ocservService.GenerateSelfSignedCert()
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	if id, err := strconv.Atoi(c.Param("id")); err == nil && id > 0 {
		inbound, err := a.inboundService.GetInbound(id)
		if err != nil {
			jsonMsg(c, "Inbound not found", err)
			return
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			jsonMsg(c, "Failed to parse settings", err)
			return
		}
		// Self-signed material lands in content mode (tlsUseFile=false).
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey

		settingsJSON, _ := json.Marshal(settings)
		inbound.Settings = string(settingsJSON)
		if _, _, err := a.inboundService.UpdateInbound(inbound); err != nil {
			jsonMsg(c, "Failed to save certificate", err)
			return
		}
		a.onOcservChanged()
	}

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
	}, nil)
}

// generateSstpCert generates a self-signed server certificate + key for SSTP
// (accel-ppp). Like generateOcservCert it works with or without a saved inbound:
// with a valid id the material is persisted to the inbound (content mode) and
// applied; otherwise it is returned for the frontend to store in the form until the
// inbound is saved. The Windows SSTP client's stricter trust requirements are
// surfaced by a warning in the UI, not changed here.
func (a *InboundController) generateSstpCert(c *gin.Context) {
	serverCert, serverKey, err := a.sstpService.GenerateSelfSignedCert()
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	if id, err := strconv.Atoi(c.Param("id")); err == nil && id > 0 {
		inbound, err := a.inboundService.GetInbound(id)
		if err != nil {
			jsonMsg(c, "Inbound not found", err)
			return
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			jsonMsg(c, "Failed to parse settings", err)
			return
		}
		// Self-signed material lands in content mode (tlsUseFile=false).
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey

		settingsJSON, _ := json.Marshal(settings)
		inbound.Settings = string(settingsJSON)
		if _, _, err := a.inboundService.UpdateInbound(inbound); err != nil {
			jsonMsg(c, "Failed to save certificate", err)
			return
		}
		a.onSstpChanged()
	}

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
	}, nil)
}

// generateIkev2Cert generates a self-signed RSA CA + server certificate for IKEv2
// (strongSwan). Unlike SSTP/ocserv it returns a CA too — the client must trust it
// (import the CA) unless a publicly-trusted cert is used. With a saved inbound the
// material is persisted (content mode) and applied; otherwise it is returned for the
// form to hold until save. The native-client self-signed caveat is surfaced in the UI.
func (a *InboundController) generateIkev2Cert(c *gin.Context) {
	serverCert, serverKey, caCert, err := a.ikev2Service.GenerateSelfSignedCert("")
	if err != nil {
		jsonMsg(c, "Failed to generate certificate", err)
		return
	}

	if id, err := strconv.Atoi(c.Param("id")); err == nil && id > 0 {
		inbound, err := a.inboundService.GetInbound(id)
		if err != nil {
			jsonMsg(c, "Inbound not found", err)
			return
		}
		var settings map[string]any
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			jsonMsg(c, "Failed to parse settings", err)
			return
		}
		settings["tlsUseFile"] = false
		settings["certificate"] = serverCert
		settings["key"] = serverKey
		settings["caCert"] = caCert

		settingsJSON, _ := json.Marshal(settings)
		inbound.Settings = string(settingsJSON)
		if _, _, err := a.inboundService.UpdateInbound(inbound); err != nil {
			jsonMsg(c, "Failed to save certificate", err)
			return
		}
		a.onIkev2Changed()
	}

	jsonObj(c, map[string]string{
		"certificate": serverCert,
		"key":         serverKey,
		"caCert":      caCert,
	}, nil)
}

// getWgcConfigs renders the WireGuard (C) client configuration(s) for one account
// (?email=) of an inbound: one .conf per device (K = the account's User Limit), with
// server-minted keys and the panel-access host as the endpoint. Ensures keys exist first.
func (a *InboundController) getWgcConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	// Mint/persist any missing server + device keypairs so the render has keys to use.
	a.wgcService.ReconcileAllKeys()
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.wgcService.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// checkIkev2Cert inspects the supplied IKEv2 server certificate's public-key type
// and returns a device-compatibility warning (non-RSA → iOS silently rejects it).
// Non-blocking: the UI surfaces the warning; it does not prevent saving.
func (a *InboundController) checkIkev2Cert(c *gin.Context) {
	data := &model.Inbound{}
	if err := c.ShouldBind(data); err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	keyType, warning, err := a.ikev2Service.InspectServerCert(data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, map[string]string{"keyType": keyType, "warning": warning}, nil)
}

// delInboundClientByEmail deletes a client from an inbound by email address.
func (a *InboundController) delInboundClientByEmail(c *gin.Context) {
	inboundId, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}

	email := c.Param("email")
	needRestart, err := a.inboundService.DelInboundClientByEmail(inboundId, email)
	if err != nil {
		jsonMsg(c, "Failed to delete client by email", err)
		return
	}

	jsonMsg(c, "Client deleted successfully", nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}
