package controller

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"
	"github.com/mhsanaei/3x-ui/v2/xray"

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
	awgService     service.AwgService
	mtprotoService service.MtprotoService
	sshService     service.SshService
}

// NewInboundController creates a new InboundController and sets up its routes.
func NewInboundController(g *gin.RouterGroup) *InboundController {
	a := &InboundController{}
	a.initRouter(g)
	return a
}

// initRouter initializes the routes for inbound-related operations.
func (a *InboundController) initRouter(g *gin.RouterGroup) {

	// Every route here needs BOTH a permission (whether the caller may do this at
	// all) and an ownership assertion (which objects they may do it to). A bit alone
	// would let any admin with "edit inbound" edit everyone's inbounds.
	//
	// /list is already scoped by user_id inside the service, and /add, /import and
	// the id-less cert generators have no existing object to authorize against.
	owns := requireInboundAccess()
	ownsClient := requireClientAccess()
	read := requirePerm(model.PermAccessInbounds)

	g.GET("/list", read, a.getInbounds)
	// The reseller's own balance, for the chip the inbounds page refreshes after
	// every operation. Gated on the read bit rather than on the role: it answers
	// "not a reseller" for everyone else, so the page needs no branch before
	// calling it.
	g.GET("/resellerBalance", read, a.resellerBalance)
	g.GET("/get/:id", read, owns, a.getInbound)
	g.GET("/getClientTraffics/:email", read, ownsClient, a.getClientTraffics)
	// NOTE: this :id is a CLIENT id (a UUID, or a username for the VPN protocols),
	// NOT an inbound id, so requireInboundOwner must not be used here: it would Atoi
	// the UUID (404ing the route for every non-super admin) and, for a numeric
	// username, check ownership of an unrelated inbound with that id. Scoped in the
	// handler instead.
	g.GET("/getClientTrafficsById/:id", read, a.getClientTrafficsById)

	g.POST("/add", requirePerm(model.PermCreateInbound), a.addInbound)
	g.POST("/del/:id", requirePerm(model.PermDeleteInbound), owns, a.delInbound)
	g.POST("/update/:id", requirePerm(model.PermEditInbound), owns, a.updateInbound)
	g.POST("/clientIps/:email", read, ownsClient, a.getClientIps)
	g.POST("/clearClientIps/:email", requirePerm(model.PermEditClient), ownsClient, a.clearClientIps)
	g.POST("/addClient", requirePerm(model.PermCreateClient), a.addInboundClient)
	g.POST("/:id/copyClients", requirePerm(model.PermCreateClient), owns, a.copyInboundClients)
	g.POST("/:id/delClient/:clientId", requirePerm(model.PermDeleteClient), owns, a.delInboundClient)
	g.POST("/updateClient/:clientId", requirePerm(model.PermEditClient), a.updateInboundClient)
	g.POST("/bulkUpdateClients", requirePerm(model.PermBulkOperation), a.bulkUpdateClients)
	g.POST("/bulkPreview", requirePerm(model.PermBulkOperation), a.bulkPreview)
	// ownsClient as well as owns: the service resolves this one by :email and ignores
	// :id, so guarding only :id checks the wrong object.
	g.POST("/:id/resetClientTraffic/:email", requirePerm(model.PermEditClient), owns, ownsClient, a.resetClientTraffic)
	g.POST("/resetAllTraffics", requirePerm(model.PermBulkOperation), a.resetAllTraffics)
	g.POST("/resetAllClientTraffics/:id", requirePerm(model.PermBulkOperation), owns, a.resetAllClientTraffics)
	g.POST("/delDepletedClients/:id", requirePerm(model.PermDeleteClient), owns, a.delDepletedClients)
	g.POST("/import", requirePerm(model.PermCreateInbound), a.importInbound)
	g.POST("/onlines", read, a.onlines)
	g.POST("/lastOnline", read, a.lastOnline)
	g.POST("/updateClientTraffic/:email", requirePerm(model.PermEditClient), ownsClient, a.updateClientTraffic)
	g.POST("/:id/delClientByEmail/:email", requirePerm(model.PermDeleteClient), owns, a.delInboundClientByEmail)
	g.GET("/:id/ovpn/:proto", read, owns, a.downloadOvpn)
	g.POST("/:id/generate-openvpn-certs", requirePerm(model.PermEditInbound), owns, a.generateOpenVpnCerts)
	// id-less variant so certs can be generated for a not-yet-saved inbound
	g.POST("/generate-openvpn-certs", requirePerm(model.PermCreateInbound), a.generateOpenVpnCerts)
	g.POST("/:id/generate-ocserv-cert", requirePerm(model.PermEditInbound), owns, a.generateOcservCert)
	g.POST("/generate-ocserv-cert", requirePerm(model.PermCreateInbound), a.generateOcservCert)
	g.POST("/:id/generate-sstp-cert", requirePerm(model.PermEditInbound), owns, a.generateSstpCert)
	g.POST("/generate-sstp-cert", requirePerm(model.PermCreateInbound), a.generateSstpCert)
	g.POST("/:id/generate-ikev2-cert", requirePerm(model.PermEditInbound), owns, a.generateIkev2Cert)
	g.POST("/generate-ikev2-cert", requirePerm(model.PermCreateInbound), a.generateIkev2Cert)
	g.POST("/check-ikev2-cert", requirePerm(model.PermCreateInbound), a.checkIkev2Cert)
	// WireGuard (C): render a client's per-device .conf(s) (keys are server-minted).
	g.GET("/:id/wgc-configs", read, owns, a.getWgcConfigs)
	// AmneziaWG: render a client's per-device .conf(s) with obfuscation (server-minted keys).
	g.GET("/:id/awg-configs", read, owns, a.getAwgConfigs)
	g.GET("/:id/ssh-configs", read, owns, a.getSshConfigs)
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
	} else {
		// Client-only changes hot-reload a running telemt via its config watcher, but
		// when this change produces the inbound's first usable account nothing has
		// launched the process yet. Start it if down (never supersedes a live one).
		if err := a.mtprotoService.EnsureServicesRunning(); err != nil {
			logger.Warning("MTProto: ensure-running failed:", err)
		}
	}
	a.mtprotoService.KillDisabledSessions()
	// The paired socks inbound (and thus this inbound's routing tag) is built from
	// the mtproto settings, so Xray must pick the change up.
	a.xrayService.SetToNeedRestart()
}

// onSshChanged reconciles the SSH gateway when an inbound is modified. Like mtproto
// there is no addressing to expand (a relay has no 10.x pool) and no nftables routing
// (egress reaches Xray through the paired socks inbound). Client-only changes do NOT
// rebind the listeners: the auth callback reads the DB live, so add/edit/disable takes
// effect on the next connection. Inbound-level changes (port, host key) rebind.
func (a *InboundController) onSshChanged()       { a.sshChanged(false) }
func (a *InboundController) onSshClientChanged() { a.sshChanged(true) }
func (a *InboundController) sshChanged(clientOnly bool) {
	if err := a.sshService.ReconcileHostKeys(); err != nil {
		logger.Warning("SSH: host key reconcile failed:", err)
	}
	if !clientOnly {
		if err := a.sshService.RestartServices(); err != nil {
			logger.Warning("SSH: service restart failed:", err)
		}
	}
	a.sshService.KillDisabledSessions()
	// The paired socks inbound (its account list and this inbound's routing tag) is
	// built from the SSH settings, so Xray must pick the change up.
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

// onAwgChanged / onAwgClientChanged reconcile AmneziaWG identically to wg-c (see wgcChanged):
// grow the 10.8 pool, mint server/device keys + obfuscation params, rebuild the kernel peer
// set, re-apply routing. No daemon; each inbound is a kernel awg<id> interface.
func (a *InboundController) onAwgChanged()       { a.awgChanged(false) }
func (a *InboundController) onAwgClientChanged() { a.awgChanged(true) }
func (a *InboundController) awgChanged(clientOnly bool) {
	expanded := service.AutoExpandVpnRanges("awg")
	a.awgService.ReconcileAllKeys()
	if err := a.awgService.GenerateAllConfigs(); err != nil {
		logger.Warning("AmneziaWG: config generation failed:", err)
	}
	if err := a.awgService.SetupRouting(); err != nil {
		logger.Warning("AmneziaWG: routing setup failed:", err)
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
	inbounds, err := a.inboundService.GetInboundsFor(user)
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
	// /list goes through GetInboundsFor, which scopes a reseller down to their own
	// accounts. This route does not, and it hands back the SAME row: the whole
	// settings blob, every client on the inbound and their credentials. The `owns`
	// middleware passes, because a reseller really does hold this inbound, so
	// without this one call the role's central promise fails on a single GET.
	if !a.filterInboundForCaller(c, inbound) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	jsonObj(c, inbound, nil)
}

// filterInboundForCaller narrows a single inbound to the clients the caller may
// see, in place. Reports false when the answer cannot be worked out, which the
// caller must treat as a refusal rather than as "nothing to filter": an
// ownership question this panel cannot answer never resolves to allowed.
//
// A no-op for anyone who is not a reseller. An admin granted an inbound sees
// every client on it, which is the existing behaviour and not something this
// role changes.
func (a *InboundController) filterInboundForCaller(c *gin.Context, inbound *model.Inbound) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if !user.IsReseller || inbound == nil {
		return true
	}
	owned, err := resellerService.OwnedEmails(user.Id)
	if err != nil {
		return false
	}
	a.inboundService.FilterInboundForReseller(inbound, owned)
	return true
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
	// The lookup is panel-wide (it matches the client id across every inbound), so
	// the result is filtered to what the caller owns. Route middleware cannot do this
	// one: the path param is a client id, not an inbound id.
	user := session.GetLoginUser(c)
	if user == nil {
		jsonObj(c, []xray.ClientTraffic{}, nil)
		return
	}
	switch {
	case user.IsSuperAdmin:
	case user.IsReseller:
		// Not the inbound filter below: a reseller holds the grant for the inbound
		// they were assigned, so filtering by it returns the admin's accounts too.
		// Ownership of the account is the only scope that means anything here.
		emails, oerr := resellerService.OwnedEmails(user.Id)
		if oerr != nil {
			jsonObj(c, []xray.ClientTraffic{}, nil) // fail closed
			return
		}
		owned := make([]xray.ClientTraffic, 0, len(clientTraffics))
		for _, ct := range clientTraffics {
			if emails[strings.ToLower(ct.Email)] {
				owned = append(owned, ct)
			}
		}
		clientTraffics = owned
	default:
		owned := make([]xray.ClientTraffic, 0, len(clientTraffics))
		for _, ct := range clientTraffics {
			ok, oerr := accessService.CanAccessInbound(ct.InboundId, user.Id)
			if oerr != nil {
				jsonObj(c, []xray.ClientTraffic{}, nil) // fail closed
				return
			}
			if ok {
				owned = append(owned, ct)
			}
		}
		clientTraffics = owned
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
	// Access is assigned, so a creator has no grant for what they just made and the
	// inbound would vanish the moment it was created. Grant it. Super admins see
	// everything by role and need no row.
	if err == nil && inbound != nil && !user.IsSuperAdmin {
		if gerr := accessService.GrantInbound(user.Id, inbound.Id); gerr != nil {
			logger.Warning("granting the creator access to their new inbound: ", gerr)
		}
	}
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
	} else if inbound.Protocol == model.AWG {
		a.onAwgChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if inbound.Protocol == model.SSH {
		a.onSshChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket, to this admin's own sockets only.
	// The list is already scoped to user.Id, so broadcasting it panel-wide handed
	// every other admin a table that isn't theirs.
	inbounds, _ := a.inboundService.GetInboundsFor(user)
	websocket.BroadcastInboundsToUser(user.Id, inbounds)
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
	// Every reseller-owned account on this inbound, and how much each has moved,
	// captured while their traffic rows still exist. Deleting the inbound takes
	// those rows with it, so a refund priced afterwards would treat every account
	// as untouched and hand back the whole charge for all of them at once.
	var resellerUsage map[string]int64
	if owned, oerr := resellerService.OwnedEmailsOnInbound(id); oerr != nil {
		logger.Warning("listing reseller accounts before an inbound delete: ", oerr)
	} else if len(owned) > 0 {
		if resellerUsage, oerr = resellerService.UsageSnapshot(owned); oerr != nil {
			logger.Warning("reading traffic before an inbound delete: ", oerr)
		}
	}
	needRestart, err := a.inboundService.DelInbound(id)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// The mirror of the grant revocation DelInbound already does: drop every reseller
	// ownership row for this inbound, refunding what those accounts had left. Left
	// behind, the rows outlive the inbound and a recycled id inherits them.
	if rerr := resellerService.DropInbound(id, resellerUsage); rerr != nil {
		logger.Warning("dropping reseller ownership of a deleted inbound's accounts: ", rerr)
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
	} else if oldInbound != nil && oldInbound.Protocol == model.AWG {
		a.onAwgChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.SSH {
		a.onSshChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket, to this admin's own sockets only.
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInboundsFor(user)
	websocket.BroadcastInboundsToUser(user.Id, inbounds)
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
	} else if inbound.Protocol == model.AWG {
		a.onAwgChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if inbound.Protocol == model.SSH {
		a.onSshChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
	// Broadcast inbounds update via WebSocket, to this admin's own sockets only.
	user := session.GetLoginUser(c)
	inbounds, _ := a.inboundService.GetInboundsFor(user)
	websocket.BroadcastInboundsToUser(user.Id, inbounds)
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
	// The target inbound is a BODY field, so the route table cannot guard it and
	// requireInboundOwner never sees it. Without this an admin holding only
	// createClient provisions a live, fully working VPN account on another admin's
	// inbound: invisible in their own list, eating the victim's IP pool and quota.
	if !a.callerOwnsInbound(c, data.Id) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	// Prices the account against the reseller's balance, clamps the posted client to
	// their limits, and RESERVES the bytes before the account exists. Inactive for an
	// admin, who has no balance to reserve against.
	//
	// Reserve first, create second, on purpose: a failure between the two loses the
	// reseller balance an admin can hand back, where the other order would hand out a
	// live account with nothing charged for it.
	ticket, err := resellerService.PrepareClientCreate(session.GetLoginUser(c), data)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	needRestart, err := a.inboundService.AddInboundClient(data)
	if err != nil {
		// The reservation paid for an account that never landed. Give it back.
		if rerr := resellerService.Rollback(ticket); rerr != nil {
			logger.Warning("rolling back a reseller charge whose client write failed: ", rerr)
		}
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
	} else if data.Protocol == model.AWG {
		a.onAwgClientChanged()
	} else if data.Protocol == model.MTPROTO {
		a.onMtprotoClientChanged()
	} else if data.Protocol == model.SSH {
		a.onSshClientChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// copyInboundClients copies clients from source inbound to target inbound.
func (a *InboundController) copyInboundClients(c *gin.Context) {
	// An empty clientEmails copies the SOURCE inbound whole, admins' accounts
	// included, and a named list is not filtered by owner either. Both inbounds can
	// legitimately be ones the reseller was assigned, so no ownership check catches it.
	//
	// Refused rather than scoped, even though CopyInboundClientsScoped exists and
	// would restrict the source: scoping is only half of it. Every copy is a NEW
	// account carrying the source's quota, so an unpriced copy is free traffic,
	// and one route call mints as many of them as the source has clients. The
	// missing half is pricing N accounts against one balance atomically, which is
	// a reservation loop this handler has no business growing.
	//
	// TODO: price the copies (a Quote per client, reserved as one transaction),
	// then switch this to CopyInboundClientsScoped.
	if denyForReseller(c, msgResellerNoInboundWide) {
		return
	}
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
	// The SOURCE arrives in the body, so requireInboundOwner (which only sees :id,
	// the destination) never checks it. Without this an admin holding only
	// createClient copies another admin's clients (UUIDs, passwords, emails) into
	// their own inbound and reads them straight back out of /list.
	if !a.callerOwnsInbound(c, req.SourceInboundID) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
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
	// Resolved before the delete, while the client still exists, and used for two
	// separate jobs: proving the caller may delete this account at all, and naming
	// the ledger row to refund afterwards.
	email := a.clientEmailOnInbound(oldInbound, clientId)
	// deleteClient plus the inbound grant is everything this route checked, and a
	// reseller holds both for an inbound they merely share, so the account-level
	// question has to be asked here.
	if !a.callerMayTouchClient(c, email) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}

	// Read while the traffic row still exists: the delete destroys it, and a
	// refund priced afterwards would see no consumption and return the whole
	// charge.
	used, usedKnown := a.usageBeforeDelete(email)
	needRestart, err := a.inboundService.DelInboundClient(id, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// Refund AFTER the delete, the opposite order to a create, and for the same
	// reason: a refund that never runs leaves balance an admin can hand back, where a
	// refund that ran before a delete which then failed would be balance paid out for
	// an account still live and still selling. A no-op for a house-owned account.
	a.refundDeletedClient(email, used, usedKnown)
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
	} else if oldInbound != nil && oldInbound.Protocol == model.AWG {
		a.onAwgChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.MTPROTO {
		a.onMtprotoChanged()
	} else if oldInbound != nil && oldInbound.Protocol == model.SSH {
		a.onSshChanged()
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
	// The target inbound arrives in the BODY, so requireInboundOwner has no path
	// param to check and the assertion has to happen here.
	if !a.callerOwnsInbound(c, inbound.Id) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	// Prices the edit and moves the balance by the delta. This also carries the
	// ownership assertion for a reseller, which the grant check above cannot make:
	// the inbound is shared, so holding it says nothing about who created THIS
	// account. Inactive for an admin.
	ticket, err := resellerService.PrepareClientUpdate(session.GetLoginUser(c), inbound, clientId)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	needRestart, err := a.inboundService.UpdateInboundClient(inbound, clientId)
	if err != nil {
		if rerr := resellerService.Rollback(ticket); rerr != nil {
			logger.Warning("rolling back a reseller charge whose client write failed: ", rerr)
		}
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// The edit is allowed to rename the account, and the ledger is keyed on email, so
	// a rename would orphan the ownership row: the reseller loses the account from
	// their own view and the refund path could never find it again. Carried across
	// after the write, since until then the old email is still the stored one.
	if ticket.Active {
		if newEmail := postedClientEmail(inbound); newEmail != "" && newEmail != ticket.Email {
			if rerr := resellerService.RenameClient(ticket.Email, newEmail); rerr != nil {
				logger.Warning("carrying reseller ownership across a client rename: ", rerr)
			}
		}
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
	} else if inbound.Protocol == model.AWG {
		a.onAwgClientChanged()
	} else if inbound.Protocol == model.MTPROTO {
		a.onMtprotoClientChanged()
	} else if inbound.Protocol == model.SSH {
		a.onSshClientChanged()
	} else if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// bulkUpdateClients applies one operation (add/subtract days or traffic, enable,
// disable) to many selected clients at once, then regenerates the touched subsystems
// once each. The payload arrives as a JSON string in the form field "data" (the panel
// axios interceptor form-encodes bodies).
// bulkPreview prices a bulk operation without applying any part of it, so a
// reseller who cannot afford the whole batch can be offered the part they can.
//
// Writes nothing, reserves nothing. What it returns is advice: the confirmed run
// goes through bulkUpdateClients as normal and is priced again from scratch
// there, so a stale or tampered preview cannot buy anything.
func (a *InboundController) bulkPreview(c *gin.Context) {
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
	ids := make([]int, 0, len(req.Targets))
	for _, t := range req.Targets {
		ids = append(ids, t.InboundId)
	}
	if !a.callerOwnsInbounds(c, ids) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	preview, err := resellerService.PreviewBulk(session.GetLoginUser(c), &req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, preview, nil)
}

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
	// Targets are a JSON array in the body. Reject the whole batch unless the caller
	// owns every inbound named: a partial apply would be worse than a refusal.
	ids := make([]int, 0, len(req.Targets))
	for _, t := range req.Targets {
		ids = append(ids, t.InboundId)
	}
	if !a.callerOwnsInbounds(c, ids) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	// Two jobs, and the scoping is the one that cannot be skipped: the targets are
	// named by the BODY, and the check above only proves the caller reaches those
	// inbounds, which a reseller shares with the admin who assigned them. PrepareBulk
	// drops every target they do not own, then prices what is left and reserves it.
	// Inactive for an admin, whose batch is neither scoped nor charged.
	ticket, err := resellerService.PrepareBulk(session.GetLoginUser(c), &req)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// What each target has consumed, read while the rows that say so still exist:
	// a delete destroys them, and an account that reads as having consumed nothing
	// refunds its whole charge.
	var usage map[string]int64
	if req.Op == "delete" {
		var uerr error
		if usage, uerr = resellerService.BulkUsageSnapshot(req.Targets); uerr != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), uerr)
			return
		}
	}
	result, touched, err := a.inboundService.BulkUpdateClients(req)
	if err != nil {
		// The reservation paid for a batch that never landed. Give it back.
		if rerr := resellerService.RollbackBulk(ticket); rerr != nil {
			logger.Warning("rolling back a reseller bulk charge whose write failed: ", rerr)
		}
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	// Deletes are refunded after the fact, like every other delete path: a refund
	// that never runs leaves balance an admin can hand back, where one that ran
	// ahead of a failed delete would be balance paid out for a live account.
	if req.Op == "delete" {
		a.refundBulkDeleted(req.Targets, usage)
	}
	// Under days-per-GB an account's deadline is a function of its traffic, and
	// the applier above moves traffic alone. This writes the deadlines the quote
	// derived, so a bulk top-up extends the accounts it just sold bytes to
	// instead of silently leaving them to expire on the old date.
	if aerr := resellerService.ApplyBulkExpiry(ticket); aerr != nil {
		logger.Warning("applying derived expiry after a reseller bulk operation: ", aerr)
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
		case string(model.AWG):
			a.onAwgClientChanged()
		case string(model.MTPROTO):
			a.onMtprotoClientChanged()
		case string(model.SSH):
			a.onSshClientChanged()
		default:
			xrayRestart = true
		}
	}
	if xrayRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// resetClientTraffic resets the traffic counter for a specific client in an inbound.
// resetClientTraffic zeroes one client's counter.
//
// The :id is owner-checked by the route, but ResetClientTraffic resolves the client
// by EMAIL alone and ignores the id, so that check guards the wrong object: an
// admin could pass their OWN inbound id and any other admin's client email, zeroing
// the victim's usage and force-enabling a client the quota system had disabled.
// The email must be owner-checked too.
func (a *InboundController) resetClientTraffic(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.inboundUpdateSuccess"), err)
		return
	}
	email := c.Param("email")

	// Allowed for a reseller, and never free. Zeroing the counters lets the account
	// move its cleared bytes a second time against the same quota, so the reseller is
	// buying that traffic again and their balance pays for it. Unpriced, this route is
	// an unlimited-traffic button: sell 1 GB, reset, repeat. Inactive for an admin,
	// whose resets cost nothing because no balance stands behind them.
	ticket, err := resellerService.PrepareClientReset(session.GetLoginUser(c), email)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}

	needRestart, err := a.inboundService.ResetClientTraffic(id, email)
	if err != nil {
		if rerr := resellerService.Rollback(ticket); rerr != nil {
			logger.Warning("rolling back a reseller charge whose traffic reset failed: ", rerr)
		}
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
	a.onAwgClientChanged()
	a.onMtprotoClientChanged()
	a.onSshClientChanged()
}

// resetAllTraffics resets all traffic counters across all inbounds.
func (a *InboundController) resetAllTraffics(c *gin.Context) {
	// PermBulkOperation reaches this route now that resellers hold it, and "all" here
	// means every inbound the caller can see, counters and all. There is no scope to
	// narrow it to: the unit is the inbound, which a reseller shares, and the reset
	// itself is a purchase they would not be charged for. Refused, not priced.
	if denyForReseller(c, msgResellerNoInboundWide) {
		return
	}
	// "All" means the caller's own inbounds. A super admin still resets everything.
	user := session.GetLoginUser(c)
	if user == nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), errNotOwned)
		return
	}
	ownerId := user.Id
	if user.IsSuperAdmin {
		ownerId = 0 // 0 = every owner
	}
	err := a.inboundService.ResetAllTraffics(ownerId)
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
	a.onAwgClientChanged()
	a.onMtprotoClientChanged()
	a.onSshClientChanged()
}

// resetAllClientTraffics resets traffic counters for all clients in a specific inbound.
func (a *InboundController) resetAllClientTraffics(c *gin.Context) {
	// Same as resetAllTraffics, one inbound narrower and no less unscoped: every
	// client on the inbound includes the admin's and every other reseller's. The
	// per-account route beside this one is the priced way to do it.
	if denyForReseller(c, msgResellerNoInboundWide) {
		return
	}
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
	a.onAwgClientChanged()
	a.onMtprotoClientChanged()
	a.onSshClientChanged()
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
	if err == nil && inbound != nil && !user.IsSuperAdmin {
		if gerr := accessService.GrantInbound(user.Id, inbound.Id); gerr != nil {
			logger.Warning("granting the creator access to their imported inbound: ", gerr)
		}
	}
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

	// "Every depleted client on this inbound" is defined over accounts a reseller
	// does not own: deleteClient plus the inbound grant is all this route checks,
	// and both hold for a reseller on an inbound they share with the admin and
	// with other resellers. So the sweep is narrowed to their own accounts rather
	// than refused, and each one it removes is refunded, exactly as a one-by-one
	// delete would have been. A depleted account refunds nothing in practice, but
	// the ledger row still has to go or a recycled email inherits it.
	user := session.GetLoginUser(c)
	if user != nil && user.IsReseller {
		owned, oerr := resellerService.OwnedEmails(user.Id)
		if oerr != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), oerr)
			return
		}
		// Snapshot every account this sweep could remove BEFORE it runs. These are
		// depleted accounts, so their refunds should be nil; priced after the
		// delete they would each return their whole charge instead.
		ownedList := make([]string, 0, len(owned))
		for e := range owned {
			ownedList = append(ownedList, e)
		}
		usage, uerr := resellerService.UsageSnapshot(ownedList)
		if uerr != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), uerr)
			return
		}
		deleted, derr := a.inboundService.DelDepletedClientsScoped(id, owned)
		if derr != nil {
			jsonMsg(c, I18nWeb(c, "somethingWentWrong"), derr)
			return
		}
		for _, email := range deleted {
			u, known := usage[strings.ToLower(strings.TrimSpace(email))]
			a.refundDeletedClient(email, u, known)
		}
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.delDepletedClientsSuccess"), nil)
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
	// Both this and lastOnline return a panel-wide list of client emails, which is
	// per-admin data. Scoping only the websocket broadcast would have been
	// cosmetic: the same two datasets are one unfiltered POST away.
	jsonObj(c, a.scopeEmails(c, a.inboundService.GetOnlineClients()), nil)
}

// lastOnline retrieves the last online timestamps for clients.
func (a *InboundController) lastOnline(c *gin.Context) {
	data, err := a.inboundService.GetClientsLastOnline()
	if err != nil {
		jsonObj(c, data, err)
		return
	}
	user := session.GetLoginUser(c)
	if user == nil {
		jsonObj(c, map[string]int64{}, nil)
		return
	}
	if user.IsSuperAdmin {
		jsonObj(c, data, nil)
		return
	}
	mine := make(map[string]int64, len(data))
	if user.IsReseller {
		// The grant map below would hand a reseller every account on the inbounds
		// they were assigned, admins' included; only ownership scopes them.
		emails, oerr := resellerService.OwnedEmails(user.Id)
		if oerr != nil {
			jsonObj(c, map[string]int64{}, nil)
			return
		}
		for email, t := range data {
			if emails[strings.ToLower(email)] {
				mine[email] = t
			}
		}
		jsonObj(c, mine, nil)
		return
	}
	access, oerr := accessService.ClientEmailAccess()
	if oerr != nil {
		// Fail closed: an ownership lookup we cannot do must not default to
		// handing over every admin's clients.
		jsonObj(c, map[string]int64{}, nil)
		return
	}
	for email, t := range data {
		if access[email][user.Id] {
			mine[email] = t
		}
	}
	jsonObj(c, mine, nil)
}

// scopeEmails filters a panel-wide list of client emails down to the caller's own.
// Super admins see everything, an admin sees the clients on inbounds they hold, and
// a reseller sees only the accounts they created: the inbound they were assigned is
// shared, so a grant-based filter would show them the admin's roster on it.
// Fails CLOSED: if ownership cannot be resolved, nothing is returned.
func (a *InboundController) scopeEmails(c *gin.Context, emails []string) []string {
	user := session.GetLoginUser(c)
	if user == nil {
		return []string{}
	}
	if user.IsSuperAdmin {
		return emails
	}
	mine := make([]string, 0, len(emails))
	if user.IsReseller {
		owned, err := resellerService.OwnedEmails(user.Id)
		if err != nil {
			return []string{}
		}
		for _, email := range emails {
			if owned[strings.ToLower(email)] {
				mine = append(mine, email)
			}
		}
		return mine
	}
	access, err := accessService.ClientEmailAccess()
	if err != nil {
		return []string{}
	}
	for _, email := range emails {
		if access[email][user.Id] {
			mine = append(mine, email)
		}
	}
	return mine
}

// updateClientTraffic updates the traffic statistics for a client by email.
func (a *InboundController) updateClientTraffic(c *gin.Context) {
	// Writing the counters by hand is the same giveaway as resetting them, one field
	// wider: see resetClientTraffic.
	if denyForReseller(c, msgResellerNoTrafficWrite) {
		return
	}
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
	// The account is a QUERY param, so no middleware sees it, and what comes back is
	// that account's private keys. `owns` on :id is enough for an admin and not for a
	// reseller, who shares the inbound with the admin whose accounts are on it.
	if !a.callerMayTouchClient(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
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

// getAwgConfigs renders the AmneziaWG client configuration(s) for one account (?email=) of an
// inbound: identical to getWgcConfigs but each [Interface] carries the obfuscation params.
func (a *InboundController) getAwgConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	// See getWgcConfigs: the account is a query param and the payload is its keys.
	if !a.callerMayTouchClient(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	a.awgService.ReconcileAllKeys()
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.awgService.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "somethingWentWrong"), err)
		return
	}
	jsonObj(c, configs, nil)
}

// getSshConfigs renders the SSH client artifacts for one account (?email=) of an
// inbound: a sing-box "ssh" outbound JSON plus a plaintext host/port/user/pass block,
// one per endpoint (each external proxy, else the panel-access host). Ensures the
// server host key exists first so the config is complete.
func (a *InboundController) getSshConfigs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		jsonMsg(c, "Invalid inbound ID", err)
		return
	}
	// See getWgcConfigs: the account is a query param and the payload is its password.
	if !a.callerMayTouchClient(c, c.Query("email")) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}
	if err := a.sshService.ReconcileHostKeys(); err != nil {
		logger.Warning("SSH: host key reconcile failed:", err)
	}
	inbound, err := a.inboundService.GetInbound(id)
	if err != nil {
		jsonMsg(c, "Inbound not found", err)
		return
	}
	configs, err := a.sshService.RenderClientConfigs(inbound, c.Query("email"), browserHost(c))
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
	// This route carries `owns` on :id but no ownsClient, because for an admin the
	// two are the same question. For a reseller they are not; see delInboundClient.
	if !a.callerMayTouchClient(c, email) {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.notFound"), errNotOwned)
		return
	}

	used, usedKnown := a.usageBeforeDelete(email)
	needRestart, err := a.inboundService.DelInboundClientByEmail(inboundId, email)
	if err != nil {
		jsonMsg(c, "Failed to delete client by email", err)
		return
	}
	// After the delete, never before; see delInboundClient. The consumption it is
	// priced against had to be read before, for the same reason.
	a.refundDeletedClient(email, used, usedKnown)

	jsonMsg(c, "Client deleted successfully", nil)
	if needRestart {
		a.xrayService.SetToNeedRestart()
	}
}

// callerOwnsInbound reports whether the logged-in admin may act on this inbound.
// Super admins may act on any. Used where the target comes from the request BODY
// rather than a path param, so requireInboundAccess cannot see it.
func (a *InboundController) callerOwnsInbound(c *gin.Context, inboundId int) bool {
	return a.callerOwnsInbounds(c, []int{inboundId})
}

// postedClientEmail reads the account name out of a client-mutating request body.
// Empty when the body does not carry exactly one client, which every one of those
// routes does; more than one would mean a single charge paid for several accounts.
func postedClientEmail(data *model.Inbound) string {
	var settings struct {
		Clients []struct {
			Email string `json:"email"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(data.Settings), &settings); err != nil {
		return ""
	}
	if len(settings.Clients) != 1 {
		return ""
	}
	return settings.Clients[0].Email
}

// clientEmailOnInbound resolves a route's :clientId back to the account email that
// both the ledger and every ownership check key on.
//
// The identity field is protocol-dependent (a UUID for vmess and vless, the
// password for the PPP protocols, the email itself for shadowsocks, auth for
// hysteria) and only the inbound service knows which one applies to a given
// protocol. So this matches against all of them and trusts the answer only when
// EXACTLY ONE client matches. That is not a shortcut: the service matches on one of
// these same fields, so its match is always among these, and a unique match here is
// therefore necessarily its match. Anything ambiguous or absent resolves to "",
// which every caller reads as a refusal.
func (a *InboundController) clientEmailOnInbound(inbound *model.Inbound, clientId string) string {
	if inbound == nil || clientId == "" {
		return ""
	}
	clients, err := a.inboundService.GetClients(inbound)
	if err != nil {
		return ""
	}
	found := ""
	for _, cl := range clients {
		if cl.ID != clientId && cl.Password != clientId && cl.Email != clientId && cl.Auth != clientId {
			continue
		}
		if found != "" && found != cl.Email {
			return "" // two clients answer to this id; refuse rather than guess
		}
		found = cl.Email
	}
	return found
}

// callerMayTouchClient is requireClientAccess's question for the routes whose target
// is not an :email path param, and so cannot be answered by middleware.
//
// True for anyone who is not a reseller: an admin's claim on a client IS the inbound
// grant, which the route table already checked. For a reseller the grant proves
// nothing, because the inbound is shared with the admin who assigned it and with
// every other reseller on it.
func (a *InboundController) callerMayTouchClient(c *gin.Context, email string) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if !user.IsReseller {
		return true
	}
	if email == "" {
		return false
	}
	owns, err := resellerService.OwnsClientEmail(email, user.Id)
	return err == nil && owns
}

// refundBulkDeleted credits back the accounts a bulk delete really removed.
//
// Not every target is one. The applier honours the skip toggles, and it always
// RETAINS one client so an inbound is never emptied, so a target can come back
// still live. Refunding one of those would hand a reseller balance for an account
// that is still selling, which is why this asks the inbound what survived rather
// than assuming the request got what it asked for.
//
// Run for admins too: an admin deleting a reseller's accounts refunds them, since
// they did not choose it, and the refund is a no-op for house-owned ones.
//
// usage is the pre-delete consumption snapshot. It has to be passed in rather than
// looked up here, because the delete has already destroyed what it measures; see
// ResellerService.RefundDeleted.
func (a *InboundController) refundBulkDeleted(targets []service.BulkClientTarget, usage map[string]int64) {
	survivors := map[int]map[string]bool{}
	for _, t := range targets {
		if t.Email == "" {
			continue
		}
		left, ok := survivors[t.InboundId]
		if !ok {
			inbound, err := a.inboundService.GetInbound(t.InboundId)
			if err != nil || inbound == nil {
				continue // cannot prove the account went, so it keeps its charge
			}
			clients, cerr := a.inboundService.GetClients(inbound)
			if cerr != nil {
				continue
			}
			left = make(map[string]bool, len(clients))
			for _, cl := range clients {
				left[strings.ToLower(strings.TrimSpace(cl.Email))] = true
			}
			survivors[t.InboundId] = left
		}
		key := strings.ToLower(strings.TrimSpace(t.Email))
		if left[key] {
			continue
		}
		u, known := usage[key]
		if err := resellerService.RefundDeleted(t.Email, u, known); err != nil {
			logger.Warning("refunding a reseller for a bulk-deleted account: ", err)
		}
	}
}

// resellerBalance reports what the caller has left to sell, so the page can show
// it after every operation rather than only on load. Answers IsReseller false and
// zeroes for an admin, which is not an error: they sell out of no balance.
func (a *InboundController) resellerBalance(c *gin.Context) {
	jsonObj(c, resellerService.BalanceFor(session.GetLoginUser(c)), nil)
}

// refundDeletedClient credits the unused part of a deleted account back to the
// reseller who sold it and forgets it. A no-op for an account the house owns, so
// every delete path can call it unconditionally.
//
// An admin deleting a reseller's account refunds them too: they did not choose it.
func (a *InboundController) refundDeletedClient(email string, allTimeAtDelete int64, known bool) {
	if email == "" {
		return
	}
	if err := resellerService.RefundDeleted(email, allTimeAtDelete, known); err != nil {
		logger.Warning("refunding a reseller for a deleted account: ", err)
	}
}

// usageBeforeDelete captures how much an account has moved in its lifetime,
// while the row that says so still exists.
//
// Deleting a client runs DelClientStat, which removes that row, so a refund
// computed afterwards sees zero consumption and returns the WHOLE charge. Every
// delete path therefore calls this first and carries the number across the
// delete; a zero on failure is the safe direction, since it refunds nothing.
func (a *InboundController) usageBeforeDelete(email string) (int64, bool) {
	if email == "" {
		return 0, false
	}
	used, known, err := resellerService.UsageOf(email)
	if err != nil {
		logger.Warning("reading traffic before a delete, refund will be withheld: ", err)
		return 0, false
	}
	return used, known
}

func (a *InboundController) callerOwnsInbounds(c *gin.Context, inboundIds []int) bool {
	user := session.GetLoginUser(c)
	if user == nil {
		return false
	}
	if user.IsSuperAdmin {
		return true
	}
	owns, err := accessService.CanAccessAllInbounds(inboundIds, user.Id)
	return err == nil && owns
}
