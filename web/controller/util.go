package controller

import (
	"net"
	"net/http"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/entity"

	"github.com/gin-gonic/gin"
)

// getRemoteIp extracts the real IP address from the request headers or remote address.
func getRemoteIp(c *gin.Context) string {
	value := c.GetHeader("X-Real-IP")
	if value != "" {
		return value
	}
	value = c.GetHeader("X-Forwarded-For")
	if value != "" {
		ips := strings.Split(value, ",")
		return ips[0]
	}
	addr := c.Request.RemoteAddr
	ip, _, _ := net.SplitHostPort(addr)
	return ip
}

// jsonMsg sends a JSON response with a message and error status.
func jsonMsg(c *gin.Context, msg string, err error) {
	jsonMsgObj(c, msg, nil, err)
}

// jsonObj sends a JSON response with an object and error status.
func jsonObj(c *gin.Context, obj any, err error) {
	jsonMsgObj(c, "", obj, err)
}

// jsonMsgObj sends a JSON response with a message, object, and error status.
func jsonMsgObj(c *gin.Context, msg string, obj any, err error) {
	m := entity.Msg{
		Obj: obj,
	}
	if err == nil {
		m.Success = true
		if msg != "" {
			m.Msg = msg
		}
	} else {
		m.Success = false
		errStr := err.Error()
		if errStr != "" {
			m.Msg = msg + " (" + errStr + ")"
			logger.Warning(msg+" "+I18nWeb(c, "fail")+": ", err)
		} else if msg != "" {
			m.Msg = msg
			logger.Warning(msg + " " + I18nWeb(c, "fail"))
		} else {
			m.Msg = I18nWeb(c, "somethingWentWrong")
			logger.Warning(I18nWeb(c, "somethingWentWrong") + " " + I18nWeb(c, "fail"))
		}
	}
	c.JSON(http.StatusOK, m)
}

// pureJsonMsg sends a pure JSON message response with custom status code.
func pureJsonMsg(c *gin.Context, statusCode int, success bool, msg string) {
	c.JSON(statusCode, entity.Msg{
		Success: success,
		Msg:     msg,
	})
}

// browserHost returns the host the client used to reach the panel (the browser
// address-bar host, with the port stripped): X-Forwarded-Host / X-Real-IP for
// reverse-proxied setups, otherwise the request Host. This is the server-side
// equivalent of the location.hostname that xray share-links use, so server-generated
// configs (e.g. .ovpn) can point at whatever address the operator is actually using.
func browserHost(c *gin.Context) string {
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.GetHeader("X-Real-IP")
	}
	if host == "" {
		h, _, err := net.SplitHostPort(c.Request.Host)
		if err != nil {
			h = c.Request.Host
		}
		host = h
	}
	return host
}

// html renders an HTML template with the provided data and title.
func html(c *gin.Context, name string, title string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data["title"] = title
	data["host"] = browserHost(c)
	data["request_uri"] = c.Request.RequestURI
	data["base_path"] = c.GetString("base_path")
	c.HTML(http.StatusOK, name, getContext(data))
}

// getContext adds version and other context data to the provided gin.H.
func getContext(h gin.H) gin.H {
	a := gin.H{
		"cur_ver": config.GetVersion(),
	}
	for key, value := range h {
		a[key] = value
	}
	return a
}

// isAjax checks if the request is an AJAX request.
func isAjax(c *gin.Context) bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}
