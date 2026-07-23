package controller

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// Self-inflicted lockouts the Admins UI refuses. The service enforces that a panel
// always retains a super admin; these catch the narrower case of the caller doing
// it to themselves, where the service cannot tell who is asking.
var (
	errSelfDemote = errors.New("you cannot remove your own super admin role or disable your own account")
	errSelfDelete = errors.New("you cannot delete your own account")
	// errNotOwned is reported as a not-found so it cannot confirm that an object with
	// that id exists under another admin.
	errNotOwned = errors.New("not found")
)

// Permission gating. This is the ONLY enforcement: hiding a nav item or a page
// section in the UI is cosmetic, since the routes stay reachable by direct request.
//
// Note that /panel and /panel/api are SIBLING Gin groups despite the URL nesting,
// so middleware on /panel does not cover /panel/api. Both must be gated.

// deny aborts the request, matching the shape each caller expects: a JSON error
// for XHR, a redirect for a page navigation.
//
// The XHR case answers HTTP 200 with success:false, which is this panel's
// convention everywhere (see jsonMsg). It matters: axios REJECTS any non-2xx, so a
// real 403 never reaches the success/msg handling and the user is shown axios's own
// "Request failed with status code 403" instead of what actually went wrong. The
// status argument is kept for the 401 case, which the frontend does treat specially.
func deny(c *gin.Context, status int, msgKey string, redirectTo string) {
	if !wantsHTML(c) {
		// Anything that is not a page navigation gets JSON, even without the ajax
		// header. Keying purely on X-Requested-With was wrong: a request that missed
		// the header got a 307 with an empty body, and the frontend surfaced that as
		// "No response data" instead of the reason. A redirect is only ever a
		// sensible answer to a browser asking for a page.
		if status == http.StatusUnauthorized {
			// Session expired: the frontend keys off the 401 to send them to login.
			pureJsonMsg(c, status, false, I18nWeb(c, msgKey))
			c.Abort()
			return
		}
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, msgKey))
		c.Abort()
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, redirectTo)
	c.Abort()
}

// wantsHTML reports whether this is a browser navigating to a page, as opposed to
// a call expecting data. Only the former should ever be redirected.
//
// A page navigation is a GET whose Accept asks for HTML. Every API call fails at
// least one of those: a POST is never a navigation, and axios sends Accept:
// application/json, */*. The ajax header is treated as a definitive "not a
// navigation" but is no longer required, so a call that omits it still gets a
// readable error rather than an empty redirect body.
func wantsHTML(c *gin.Context) bool {
	if isAjax(c) {
		return false
	}
	if c.Request.Method != http.MethodGet {
		return false
	}
	return strings.Contains(c.GetHeader("Accept"), "text/html")
}

// requirePerm gates a route on a single permission. Super admins always pass.
func requirePerm(perm model.Permission) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			// Logged out, deleted mid-session, or disabled.
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !user.Can(perm) {
			// Authenticated but not allowed: send a page navigation to the overview
			// rather than a dead end, since every admin can see that.
			deny(c, http.StatusForbidden, "pages.admins.forbidden", c.GetString("base_path")+"panel/")
			return
		}
		c.Next()
	}
}

// requireSuperAdmin gates the escalation-class routes that no permission bit can
// safely stand in for, because reaching any of them yields the whole panel:
// exporting or importing the SQLite DB (every admin's bcrypt hash), mailing it to
// Telegram, replacing the panel binary, writing the systemd unit as root, and
// rebooting the host. It also gates admin management itself.
func requireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if !user.IsSuperAdmin {
			deny(c, http.StatusForbidden, "pages.admins.forbidden", c.GetString("base_path")+"panel/")
			return
		}
		c.Next()
	}
}

// accessService backs the access middleware below. AdminService is stateless.
var accessService service.AdminService

// resellerService answers the question an inbound grant cannot: WHICH accounts on a
// shared inbound belong to the caller. Stateless, like accessService.
var resellerService service.ResellerService

// denyNotFound refuses a cross-owner reference. It reports "not found" rather than
// "forbidden" on purpose: a distinguishable 403 would confirm that an inbound with
// that id exists and belongs to someone else, turning the middleware into an
// enumeration oracle over the small integer id space.
func denyNotFound(c *gin.Context) {
	if !wantsHTML(c) {
		// 200 + success:false, like every other error this panel returns: axios
		// rejects a non-2xx before the msg is ever read.
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.inbounds.notFound"))
	} else {
		c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path")+"panel/")
	}
	c.Abort()
}

// requireInboundAccess asserts the caller has been GRANTED the inbound named by the
// :id path param. Routes registered in both an :id-ful and an :id-less form (the cert
// generators, which also serve not-yet-saved inbounds) pass through when :id is
// absent; there is no object to authorize against yet.
func requireInboundAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if user.IsSuperAdmin {
			c.Next()
			return
		}
		raw := c.Param("id")
		if raw == "" {
			c.Next()
			return
		}
		id, err := strconv.Atoi(raw)
		if err != nil {
			denyNotFound(c)
			return
		}
		ok, err := accessService.CanAccessInbound(id, user.Id)
		if err != nil || !ok {
			denyNotFound(c)
			return
		}
		c.Next()
	}
}

// requireClientAccess asserts the caller may act on the client named by the :email
// path param. Client emails are a single panel-wide namespace, so without this an
// :email route reaches straight across admins.
//
// Two different questions, depending on who is asking. For an admin it is the
// inbound grant: every client on an inbound they hold is theirs to touch. For a
// reseller it is account ownership, and that check REPLACES the grant check rather
// than joining it. A reseller holds the grant for their assigned inbounds (that is
// how they see them at all), so CanAccessClientEmail answers true for every account
// on those inbounds, including the admin's, and supplementing would wave them
// straight through to exactly the accounts this role exists to keep them out of.
func requireClientAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := session.GetLoginUser(c)
		if user == nil {
			deny(c, http.StatusUnauthorized, "pages.login.loginAgain", c.GetString("base_path"))
			return
		}
		if user.IsSuperAdmin {
			c.Next()
			return
		}
		email := c.Param("email")
		if email == "" {
			denyNotFound(c)
			return
		}
		if user.IsReseller {
			owns, err := resellerService.OwnsClientEmail(email, user.Id)
			if err != nil || !owns {
				denyNotFound(c)
				return
			}
			c.Next()
			return
		}
		ok, err := accessService.CanAccessClientEmail(email, user.Id)
		if err != nil || !ok {
			denyNotFound(c)
			return
		}
		c.Next()
	}
}

// Refusal text for the routes a reseller can reach with the bits the role derives
// but must not use. Plain English rather than an i18n key: these are reasons, not
// labels, and the reseller has to read why a control they can see does nothing.
const (
	// Both traffic-writing routes hand an account bytes past the quota the
	// reseller's balance was debited for, and the giveaway comes off the house
	// rather than off them. Refused outright rather than priced: there is no
	// charge that makes "your counter is now zero" cost the seller anything.
	msgResellerNoTrafficWrite = "Resellers cannot change an account's traffic counters. Change the account's traffic limit instead."
	// Both inbound-wide routes are defined over every client on an inbound, which
	// a reseller shares with admins and with other resellers, so they reach
	// accounts that are not theirs.
	msgResellerNoInboundWide = "Resellers cannot run this across a whole inbound: it would reach accounts you do not own."
)

// denyForReseller refuses an operation outright when the caller is a reseller, and
// reports whether it answered the request so call sites read as a guard.
//
// Unlike denyNotFound this says forbidden, plainly. Hiding the reason behind a
// not-found would be pointless here: the route is not about some object that may or
// may not exist under another owner, and the reseller can already see the button.
func denyForReseller(c *gin.Context, msg string) bool {
	user := session.GetLoginUser(c)
	if user == nil || !user.IsReseller {
		return false
	}
	pureJsonMsg(c, http.StatusOK, false, msg)
	return true
}
