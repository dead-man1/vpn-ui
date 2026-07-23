package controller

import (
	"net/http"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// XUIController is the main controller for the vpn-ui panel, managing sub-controllers.
type XUIController struct {
	BaseController

	settingController     *SettingController
	xraySettingController *XraySettingController
	coreController        *CoreController
	adminController       *AdminController
	resellerController    *ResellerController
}

// NewXUIController creates a new XUIController and initializes its routes.
func NewXUIController(g *gin.RouterGroup) *XUIController {
	a := &XUIController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the main panel routes and initializes sub-controllers.
func (a *XUIController) initRouter(g *gin.RouterGroup) {
	g = g.Group("/panel")
	g.Use(a.checkLogin)

	// The overview is the one page every admin may see; it is where a permission
	// denial redirects to, so gating it would loop.
	g.GET("/", a.index)
	g.GET("/inbounds", requirePerm(model.PermAccessInbounds), a.inbounds)
	g.GET("/settings", requirePerm(model.PermPanelSettings), a.settings)
	g.GET("/xray", requirePerm(model.PermXraySettings), a.xraySettings)
	g.GET("/core", requirePerm(model.PermCoreSettings), a.coreSettings)
	g.GET("/admins", requireSuperAdmin(), a.admins)
	// Resellers is a permission and not requireSuperAdmin(), so a delegated admin can
	// run their own resellers. The escalation that opens (assigning someone else's
	// inbound to a reseller you then log in as) is closed in the service.
	g.GET("/resellers", requirePerm(model.PermManageResellers), a.resellers)

	a.settingController = NewSettingController(g)
	a.xraySettingController = NewXraySettingController(g)
	a.coreController = NewCoreController(g)
	a.adminController = NewAdminController(g)
	a.resellerController = NewResellerController(g)
}

// index renders the main panel index page.
func (a *XUIController) index(c *gin.Context) {
	// A reseller's home is the accounts they sell, not the machine they sell them
	// on. The overview is a host dashboard (kernel, CPU, disk, public IP, panel
	// updates) and none of it is theirs to act on, so by default they are sent to
	// the one page the role exists for. An operator can hand it back per reseller
	// with the allowOverview toggle, and the nav entry follows the same flag.
	//
	// The redirect is the control and the hidden nav entry is only the courtesy:
	// this route stays reachable by typing the URL.
	//
	// Safe as the denial target that every deny() redirects to: a reseller always
	// holds PermAccessInbounds, which resellerPerms derives rather than stores, so
	// this hop can never bounce back here and loop.
	if user := session.GetLoginUser(c); user != nil && user.IsReseller {
		var svc service.ResellerService
		if p, err := svc.ProfileFor(user.Id); err != nil || !p.AllowOverview {
			c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/inbounds")
			return
		}
	}
	html(c, "index.html", "pages.index.title", nil)
}

// inbounds renders the inbounds management page.
func (a *XUIController) inbounds(c *gin.Context) {
	html(c, "inbounds.html", "pages.inbounds.title", nil)
}

// settings renders the settings management page.
func (a *XUIController) settings(c *gin.Context) {
	html(c, "settings.html", "pages.settings.title", nil)
}

// xraySettings renders the Xray settings page.
func (a *XUIController) xraySettings(c *gin.Context) {
	html(c, "xray.html", "pages.xray.title", nil)
}

// coreSettings renders the Core Settings page (per-core status + provisioning).
func (a *XUIController) coreSettings(c *gin.Context) {
	html(c, "core.html", "pages.core.title", nil)
}

// admins renders the Admins management page (super admin only).
func (a *XUIController) admins(c *gin.Context) {
	html(c, "admins.html", "pages.admins.title", nil)
}

// resellers renders the Resellers management page.
func (a *XUIController) resellers(c *gin.Context) {
	html(c, "resellers.html", "pages.resellers.title", nil)
}
