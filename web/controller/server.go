package controller

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"

	"github.com/gin-gonic/gin"
)

var filenameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-.]+$`)

// ServerController handles server management and status-related operations.
type ServerController struct {
	BaseController

	serverService  service.ServerService
	settingService service.SettingService
	inboundService service.InboundService

	lastStatus *service.Status

	lastVersions        []string
	lastGetVersionsTime int64 // unix seconds

	updMu               sync.Mutex // guards lastPanelUpdate/lastPanelUpdateTime
	lastPanelUpdate     *service.PanelUpdateInfo
	lastPanelUpdateTime int64 // unix seconds
}

// NewServerController creates a new ServerController, initializes routes, and starts background tasks.
func NewServerController(g *gin.RouterGroup) *ServerController {
	a := &ServerController{}
	a.initRouter(g)
	a.startTask()
	return a
}

// initRouter sets up the routes for server status, Xray management, and utility endpoints.
func (a *ServerController) initRouter(g *gin.RouterGroup) {

	g.GET("/status", a.status)
	g.GET("/userStats", a.userStats)
	g.GET("/serverName", a.getServerName)
	g.GET("/cpuHistory/:bucket", a.getCpuHistoryBucket)
	g.GET("/getXrayVersion", a.getXrayVersion)
	// Escalation-class: these hand over the whole panel regardless of any
	// permission bit, so they are super-admin only. getConfigJson and getDb expose
	// every admin's data (getDb includes the users table and its bcrypt hashes);
	// importDB replaces it wholesale; updatePanel swaps the running binary.
	g.GET("/getConfigJson", requireSuperAdmin(), a.getConfigJson)
	g.GET("/getDb", requireSuperAdmin(), a.getDb)
	g.GET("/getNewUUID", a.getNewUUID)
	g.GET("/getNewX25519Cert", a.getNewX25519Cert)
	g.GET("/getNewmldsa65", a.getNewmldsa65)
	g.GET("/getNewmlkem768", a.getNewmlkem768)
	g.GET("/getNewVlessEnc", a.getNewVlessEnc)
	g.GET("/distroStatus", a.distroStatus)
	g.GET("/checkUpdate", a.checkUpdate)
	g.GET("/updateProgress", a.updateProgress)

	// Renaming the server relabels the panel for every admin, so it follows the panel
	// settings permission. Reading it stays open: the overview shows the label, and
	// every admin can see the overview.
	g.POST("/serverName", requirePerm(model.PermPanelSettings), a.setServerName)

	// Panel-wide effects rather than per-inbound, so they follow the Xray permission.
	g.POST("/stopXrayService", requirePerm(model.PermXraySettings), a.stopXrayService)
	g.POST("/updatePanel", requireSuperAdmin(), a.updatePanel)
	g.POST("/cancelUpdate", requireSuperAdmin(), a.cancelUpdate)
	g.POST("/restartXrayService", requirePerm(model.PermXraySettings), a.restartXrayService)
	g.POST("/installXray/:version", requirePerm(model.PermXraySettings), a.installXray)
	g.POST("/updateGeofile", requirePerm(model.PermXraySettings), a.updateGeofile)
	g.POST("/updateGeofile/:fileName", requirePerm(model.PermXraySettings), a.updateGeofile)
	// Panel and Xray logs name other admins' inbounds, clients and IPs.
	g.POST("/logs/:count", requireSuperAdmin(), a.getLogs)
	g.POST("/xraylogs/:count", requireSuperAdmin(), a.getXrayLogs)
	g.POST("/importDB", requireSuperAdmin(), a.importDB)
	g.POST("/getNewEchCert", a.getNewEchCert)
}

// refreshStatus updates the cached server status and collects CPU history.
func (a *ServerController) refreshStatus() {
	a.lastStatus = a.serverService.GetStatus(a.lastStatus)
	// collect cpu history when status is fresh
	if a.lastStatus != nil {
		a.serverService.AppendCpuSample(time.Now(), a.lastStatus.Cpu)
		// Broadcast status update via WebSocket
		websocket.BroadcastStatus(a.lastStatus)
	}
}

// startTask initiates background tasks for continuous status monitoring.
func (a *ServerController) startTask() {
	webServer := global.GetWebServer()
	c := webServer.GetCron()
	c.AddFunc("@every 2s", func() {
		// Always refresh to keep CPU history collected continuously.
		// Sampling is lightweight and capped to ~6 hours in memory.
		a.refreshStatus()
	})
}

// status returns the current server status information.
func (a *ServerController) status(c *gin.Context) { jsonObj(c, a.lastStatus, nil) }

// userStats returns the overview's account roll-up (total, online, depleted and
// expiring) for the logged-in admin. The inbounds page derives the same four
// numbers in the browser from the full inbound list; the overview wants only the
// counts, so it gets them without shipping every client.
func (a *ServerController) userStats(c *gin.Context) {
	stats, err := a.inboundService.GetClientStatsFor(session.GetLoginUser(c))
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.obtain"), err)
		return
	}
	jsonObj(c, stats, nil)
}

// getServerName returns the operator's label for this server, empty when unset.
func (a *ServerController) getServerName(c *gin.Context) {
	name, err := a.settingService.GetServerName()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.getSettings"), err)
		return
	}
	jsonObj(c, gin.H{"serverName": name}, nil)
}

// setServerName persists the operator's label for this server. Posting an empty
// value clears it and returns the overview to the host name.
func (a *ServerController) setServerName(c *gin.Context) {
	name := strings.TrimSpace(c.PostForm("serverName"))
	if len([]rune(name)) > 64 {
		jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"),
			errors.New("server name is limited to 64 characters"))
		return
	}
	err := a.settingService.SetServerName(name)
	jsonMsg(c, I18nWeb(c, "pages.settings.toasts.modifySettings"), err)
}

// distroStatus reports whether the running host distro is on vpn-ui's tested list,
// for the dashboard's unsupported-distro warning modal.
func (a *ServerController) distroStatus(c *gin.Context) {
	supported, pretty, reason := service.DistroSupported()
	jsonObj(c, gin.H{
		"supported": supported,
		"pretty":    pretty,
		"reason":    reason,
		"tested":    service.SupportedDistroSummary(),
	}, nil)
}

// getCpuHistoryBucket retrieves aggregated CPU usage history based on the specified time bucket.
func (a *ServerController) getCpuHistoryBucket(c *gin.Context) {
	bucketStr := c.Param("bucket")
	bucket, err := strconv.Atoi(bucketStr)
	if err != nil || bucket <= 0 {
		jsonMsg(c, "invalid bucket", fmt.Errorf("bad bucket"))
		return
	}
	allowed := map[int]bool{
		2:   true, // Real-time view
		30:  true, // 30s intervals
		60:  true, // 1m intervals
		120: true, // 2m intervals
		180: true, // 3m intervals
		300: true, // 5m intervals
	}
	if !allowed[bucket] {
		jsonMsg(c, "invalid bucket", fmt.Errorf("unsupported bucket"))
		return
	}
	points := a.serverService.AggregateCpuHistory(bucket, 60)
	jsonObj(c, points, nil)
}

// getXrayVersion retrieves available Xray versions, with caching for 1 minute.
func (a *ServerController) getXrayVersion(c *gin.Context) {
	now := time.Now().Unix()
	if now-a.lastGetVersionsTime <= 60 { // 1 minute cache
		jsonObj(c, a.lastVersions, nil)
		return
	}

	versions, err := a.serverService.GetXrayVersions()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "getVersion"), err)
		return
	}

	a.lastVersions = versions
	a.lastGetVersionsTime = now

	jsonObj(c, versions, nil)
}

// checkUpdate reports whether a newer vpn-ui panel release is available. The
// result is cached for 5 minutes — including FAILURES (negative cache) — so the
// per-overview-load auto-check can't burn GitHub's unauthenticated rate limit even
// during an outage. The manual button passes ?force=1 to bypass the cache.
//
// The auto-check (non-force) must stay SILENT: on error it returns via jsonObj with
// an empty message, so HttpUtil raises no toast. Only a manual check surfaces the
// error (a toast on an explicit click is expected).
func (a *ServerController) checkUpdate(c *gin.Context) {
	now := time.Now().Unix()
	force := c.Query("force") != ""

	a.updMu.Lock()
	if !force && a.lastPanelUpdate != nil && now-a.lastPanelUpdateTime <= 300 {
		cached := a.lastPanelUpdate
		a.updMu.Unlock()
		jsonObj(c, cached, nil)
		return
	}
	a.updMu.Unlock()

	info, err := a.serverService.CheckPanelUpdate()

	a.updMu.Lock()
	a.lastPanelUpdateTime = now // cache success AND failure to bound GitHub calls
	if err == nil {
		a.lastPanelUpdate = info
	} else if a.lastPanelUpdate == nil {
		// Cold start with GitHub failing: seed the benign result (info is non-nil,
		// Available=false) so the cache-hit guard engages and we stop re-hitting
		// GitHub every load. Never overwrite a prior real result with this.
		a.lastPanelUpdate = info
	}
	last := a.lastPanelUpdate
	a.updMu.Unlock()

	if err != nil {
		if force {
			jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err) // manual: surface it
			return
		}
		// auto check: stay silent (empty msg => no toast). Prefer last-known-good.
		if last != nil {
			jsonObj(c, last, nil)
		} else {
			jsonObj(c, info, nil) // benign: Available=false
		}
		return
	}
	jsonObj(c, info, nil)
}

// updatePanel downloads the latest release, replaces the running binary, and
// restarts the panel. The response returns before the restart fires. On success it
// returns an empty message (no toast) — the frontend shows the "restarting" alert;
// only failures toast.
func (a *ServerController) updatePanel(c *gin.Context) {
	err := a.serverService.UpdatePanel()
	if errors.Is(err, service.ErrPanelUpdateCancelled) {
		// The user asked for this, so it isn't a failure: report success and let the
		// frontend reset on the "cancelled" flag instead of toasting an error.
		jsonObj(c, gin.H{"cancelled": true}, nil)
		return
	}
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.panelUpdate"), err)
		return
	}
	jsonObj(c, nil, nil)
}

// cancelUpdate aborts an in-flight update download. Refused once the update reaches
// the install phase, which must not be interrupted.
func (a *ServerController) cancelUpdate(c *gin.Context) {
	if err := a.serverService.CancelPanelUpdate(); err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.updateCancel"), err)
		return
	}
	jsonObj(c, nil, nil)
}

// updateProgress reports the in-flight self-update's phase, download percent and
// byte counters, polled by the overview to render the progress bar + speed meter.
func (a *ServerController) updateProgress(c *gin.Context) {
	jsonObj(c, a.serverService.PanelUpdateProgress(), nil)
}

// installXray installs or updates Xray to the specified version.
func (a *ServerController) installXray(c *gin.Context) {
	version := c.Param("version")
	err := a.serverService.UpdateXray(version)
	jsonMsg(c, I18nWeb(c, "pages.index.xraySwitchVersionPopover"), err)
}

// updateGeofile updates the specified geo file for Xray.
func (a *ServerController) updateGeofile(c *gin.Context) {
	fileName := c.Param("fileName")

	// Validate the filename for security (prevent path traversal attacks)
	if fileName != "" && !a.serverService.IsValidGeofileName(fileName) {
		jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"),
			fmt.Errorf("invalid filename: contains unsafe characters or path traversal patterns"))
		return
	}

	err := a.serverService.UpdateGeofile(fileName)
	jsonMsg(c, I18nWeb(c, "pages.index.geofileUpdatePopover"), err)
}

// stopXrayService stops the Xray service.
func (a *ServerController) stopXrayService(c *gin.Context) {
	err := a.serverService.StopXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.stopError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.stopSuccess"), err)
	websocket.BroadcastXrayState("stop", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.stopSuccess"),
		"Xray service has been stopped",
		"warning",
	)
}

// restartXrayService restarts the Xray service.
func (a *ServerController) restartXrayService(c *gin.Context) {
	err := a.serverService.RestartXrayService()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.xray.restartError"), err)
		websocket.BroadcastXrayState("error", err.Error())
		return
	}
	jsonMsg(c, I18nWeb(c, "pages.xray.restartSuccess"), err)
	websocket.BroadcastXrayState("running", "")
	websocket.BroadcastNotification(
		I18nWeb(c, "pages.xray.restartSuccess"),
		"Xray service has been restarted successfully",
		"success",
	)
}

// getLogs retrieves the application logs based on count, level, and syslog filters.
func (a *ServerController) getLogs(c *gin.Context) {
	count := c.Param("count")
	level := c.PostForm("level")
	syslog := c.PostForm("syslog")
	logs := a.serverService.GetLogs(count, level, syslog)
	jsonObj(c, logs, nil)
}

// getXrayLogs retrieves Xray logs with filtering options for direct, blocked, and proxy traffic.
func (a *ServerController) getXrayLogs(c *gin.Context) {
	count := c.Param("count")
	filter := c.PostForm("filter")
	showDirect := c.PostForm("showDirect")
	showBlocked := c.PostForm("showBlocked")
	showProxy := c.PostForm("showProxy")

	var freedoms []string
	var blackholes []string

	//getting tags for freedom and blackhole outbounds
	config, err := a.settingService.GetDefaultXrayConfig()
	if err == nil && config != nil {
		if cfgMap, ok := config.(map[string]any); ok {
			if outbounds, ok := cfgMap["outbounds"].([]any); ok {
				for _, outbound := range outbounds {
					if obMap, ok := outbound.(map[string]any); ok {
						switch obMap["protocol"] {
						case "freedom":
							if tag, ok := obMap["tag"].(string); ok {
								freedoms = append(freedoms, tag)
							}
						case "blackhole":
							if tag, ok := obMap["tag"].(string); ok {
								blackholes = append(blackholes, tag)
							}
						}
					}
				}
			}
		}
	}

	if len(freedoms) == 0 {
		freedoms = []string{"direct"}
	}
	if len(blackholes) == 0 {
		blackholes = []string{"blocked"}
	}

	logs := a.serverService.GetXrayLogs(count, filter, showDirect, showBlocked, showProxy, freedoms, blackholes)
	jsonObj(c, logs, nil)
}

// getConfigJson retrieves the Xray configuration as JSON.
func (a *ServerController) getConfigJson(c *gin.Context) {
	configJson, err := a.serverService.GetConfigJson()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getConfigError"), err)
		return
	}
	jsonObj(c, configJson, nil)
}

// getDb downloads the database file.
func (a *ServerController) getDb(c *gin.Context) {
	db, err := a.serverService.GetDb()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.getDatabaseError"), err)
		return
	}

	filename := fmt.Sprintf("vpn-ui_%s.db", time.Now().Format("20060102-150405"))

	if !isValidFilename(filename) {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("invalid filename"))
		return
	}

	// Set the headers for the response
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", "attachment; filename="+filename)

	// Write the file contents to the response
	c.Writer.Write(db)
}

func isValidFilename(filename string) bool {
	// Validate that the filename only contains allowed characters
	return filenameRegex.MatchString(filename)
}

// importDB imports a database file and restarts the Xray service.
func (a *ServerController) importDB(c *gin.Context) {
	// Get the file from the request body
	file, _, err := c.Request.FormFile("db")
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.readDatabaseError"), err)
		return
	}
	defer file.Close()
	// Always restart Xray before return
	defer a.serverService.RestartXrayService()
	// lastGetStatusTime removed; no longer needed
	// Import it
	err = a.serverService.ImportDB(file)
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.index.importDatabaseError"), err)
		return
	}
	jsonObj(c, I18nWeb(c, "pages.index.importDatabaseSuccess"), nil)
}

// getNewX25519Cert generates a new X25519 certificate.
func (a *ServerController) getNewX25519Cert(c *gin.Context) {
	cert, err := a.serverService.GetNewX25519Cert()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewX25519CertError"), err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewmldsa65 generates a new ML-DSA-65 key.
func (a *ServerController) getNewmldsa65(c *gin.Context) {
	cert, err := a.serverService.GetNewmldsa65()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewmldsa65Error"), err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewEchCert generates a new ECH certificate for the given SNI.
func (a *ServerController) getNewEchCert(c *gin.Context) {
	sni := c.PostForm("sni")
	cert, err := a.serverService.GetNewEchCert(sni)
	if err != nil {
		jsonMsg(c, "get ech certificate", err)
		return
	}
	jsonObj(c, cert, nil)
}

// getNewVlessEnc generates a new VLESS encryption key.
func (a *ServerController) getNewVlessEnc(c *gin.Context) {
	out, err := a.serverService.GetNewVlessEnc()
	if err != nil {
		jsonMsg(c, I18nWeb(c, "pages.inbounds.toasts.getNewVlessEncError"), err)
		return
	}
	jsonObj(c, out, nil)
}

// getNewUUID generates a new UUID.
func (a *ServerController) getNewUUID(c *gin.Context) {
	uuidResp, err := a.serverService.GetNewUUID()
	if err != nil {
		jsonMsg(c, "Failed to generate UUID", err)
		return
	}

	jsonObj(c, uuidResp, nil)
}

// getNewmlkem768 generates a new ML-KEM-768 key.
func (a *ServerController) getNewmlkem768(c *gin.Context) {
	out, err := a.serverService.GetNewmlkem768()
	if err != nil {
		jsonMsg(c, "Failed to generate mlkem768 keys", err)
		return
	}
	jsonObj(c, out, nil)
}
