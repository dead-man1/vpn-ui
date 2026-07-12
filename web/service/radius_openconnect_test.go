package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/op/go-logging"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

// capRW captures the response packet handleAuth writes, so a test can assert on it
// without opening a real UDP socket.
type capRW struct{ resp *radius.Packet }

func (c *capRW) Write(p *radius.Packet) error { c.resp = p; return nil }

// TestHandleAuthOpenconnectPAP drives the panel's RADIUS auth handler with exactly
// the request ocserv/radcli is expected to send for an OpenConnect login: a PAP
// Access-Request (User-Name + User-Password) with NAS-Identifier "openconnect-<id>".
// It asserts the panel returns Access-Accept AND pins the tunnel IP via
// Framed-IP-Address — the reply ocserv needs (predictable-ips=false, RADIUS-
// authoritative). Reproduces the E2E "401 Authentication failed" on the panel side,
// with no VM/ocserv/client, so the reject reason is visible in seconds.
func TestHandleAuthOpenconnectPAP(t *testing.T) {
	logger.InitLogger(logging.DEBUG)
	if err := database.InitDB(filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	db := database.GetDB()

	// An OpenConnect inbound with one account, shaped exactly like the panel/E2E
	// store it (clients[] with id/password/email/enable; empty email skips the
	// client_traffics limit check).
	settings := `{"clients":[{"id":"ocuser","password":"ocpass","email":"","enable":true}],"ipRanges":[],"userLimit":1,"userLimitStrategy":"accept"}`
	ib := &model.Inbound{
		Enable:   true,
		Port:     4443,
		Protocol: model.OPENCONNECT,
		Settings: settings,
		Tag:      "inbound-openconnect-4443",
	}
	if err := db.Create(ib).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	t.Logf("inbound id=%d protocol=%s", ib.Id, ib.Protocol)

	const secret = "testsecret"
	s := &RadiusService{
		sessions:    map[string]*radiusSession{},
		pending:     map[string]time.Time{},
		stationIP:   map[string]string{},
		stationSeen: map[string]time.Time{},
		ocActiveFn:  func(string) bool { return true },
		secret:      []byte(secret),
	}

	// Craft the PAP Access-Request ocserv sends.
	pkt := radius.New(radius.CodeAccessRequest, []byte(secret))
	rfc2865.UserName_SetString(pkt, "ocuser")
	rfc2865.UserPassword_SetString(pkt, "ocpass")
	rfc2865.NASIdentifier_SetString(pkt, "openconnect-"+itoa(ib.Id))
	rfc2865.CallingStationID_SetString(pkt, "203.0.113.50")

	w := &capRW{}
	s.handleAuth(w, &radius.Request{Packet: pkt})

	if w.resp == nil {
		t.Fatal("handler wrote no response")
	}
	framed := rfc2865.FramedIPAddress_Get(w.resp)
	t.Logf("RESULT: code=%v framed-ip=%v", w.resp.Code, framed)

	if w.resp.Code != radius.CodeAccessAccept {
		t.Fatalf("openconnect PAP got %v, want Access-Accept — panel is REJECTING a valid login", w.resp.Code)
	}
	if framed == nil {
		t.Fatalf("Access-Accept carries NO Framed-IP-Address — ocserv (predictable-ips=false) cannot assign a tunnel IP")
	}
}
