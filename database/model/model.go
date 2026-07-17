// Package model defines the database models and data structures used by the vpn-ui panel.
package model

import (
	"fmt"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Protocol represents the protocol type for Xray inbounds.
type Protocol string

// Protocol constants for different Xray inbound protocols
const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Tunnel      Protocol = "tunnel"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Mixed       Protocol = "mixed"
	WireGuard   Protocol = "wireguard"
	L2TP        Protocol = "l2tp"
	PPTP        Protocol = "pptp"
	OPENVPN     Protocol = "openvpn"
	OPENCONNECT Protocol = "openconnect"
	SSTP        Protocol = "sstp"
	IKEV2       Protocol = "ikev2"
	WGC         Protocol = "wg-c"
	MTPROTO     Protocol = "mtproto"
	SSH         Protocol = "ssh"
	// UI stores Hysteria v1 and v2 both as "hysteria" and uses
	// settings.version to discriminate. Imports from outside the panel
	// can carry the literal "hysteria2" string, so IsHysteria below
	// accepts both.
	Hysteria  Protocol = "hysteria"
	Hysteria2 Protocol = "hysteria2"
)

// IsHysteria returns true for both "hysteria" and "hysteria2".
// Use instead of a bare ==model.Hysteria check: a v2 inbound stored
// with the literal v2 string would otherwise fall through (#4081).
func IsHysteria(p Protocol) bool {
	return p == Hysteria || p == Hysteria2
}

// ClientExternalProxy is one alternate endpoint rendered into an account's links
// instead of this server's own address (a relay/CDN in front of the proxy). It
// affects generated links only: no daemon ever reads it.
type ClientExternalProxy struct {
	Dest   string `json:"dest"`
	Port   int    `json:"port"`
	Remark string `json:"remark"`
}

// User represents an admin account in the vpn-ui panel.
//
// Password and TwoFactorToken are secrets and carry json:"-" so they can never be
// serialized out to the browser: the panel's session cookie is signed but NOT
// encrypted, so anything that reaches it is readable client-side. The session
// stores only Id for the same reason (see web/session).
type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username" gorm:"uniqueIndex"`
	Password string `json:"-"`

	// Nickname is a human label for the Admins list; it carries no privilege.
	Nickname string `json:"nickname" form:"nickname"`

	// IsSuperAdmin bypasses Permissions entirely and is the only role that may
	// manage admins. Exactly one is seeded from the pre-existing first user.
	IsSuperAdmin bool `json:"isSuperAdmin" gorm:"default:0"`

	// Permissions is the capability bitmask; ignored for a super admin.
	Permissions Permission `json:"-" gorm:"default:0"`

	// Enable gates login without deleting the account (and its owned inbounds).
	Enable bool `json:"enable" form:"enable" gorm:"default:1"`

	// Per-admin TOTP. Replaces the panel-global twoFactorEnable/twoFactorToken
	// settings pair, which leaked the shared secret to every logged-in user
	// through GetAllSetting.
	TwoFactorEnable bool   `json:"twoFactorEnable" gorm:"default:0"`
	TwoFactorToken  string `json:"-"`
}

// InboundAccess grants one admin access to one inbound.
//
// Access is ASSIGNED, not inferred from who created the row. A super admin ticks
// which inbounds each admin can see, and anything unticked does not exist as far as
// that admin is concerned. Inbound.UserId still records the creator (for the Admins
// list and Reassign), but it is bookkeeping: it does not decide access.
//
// Super admins are never listed here; they see every inbound by role.
type InboundAccess struct {
	Id        int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId    int `json:"userId" gorm:"index:idx_access_user_inbound,unique,priority:1;index"`
	InboundId int `json:"inboundId" gorm:"index:idx_access_user_inbound,unique,priority:2;index"`
}

// Inbound represents an Xray inbound configuration with traffic statistics and settings.
type Inbound struct {
	Id                   int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`                                                    // Unique identifier
	UserId               int                  `json:"-"`                                                                                               // Associated user ID
	Up                   int64                `json:"up" form:"up"`                                                                                    // Upload traffic in bytes
	Down                 int64                `json:"down" form:"down"`                                                                                // Download traffic in bytes
	Total                int64                `json:"total" form:"total"`                                                                              // Total traffic limit in bytes
	AllTime              int64                `json:"allTime" form:"allTime" gorm:"default:0"`                                                         // All-time traffic usage
	Remark               string               `json:"remark" form:"remark"`                                                                            // Human-readable remark
	Enable               bool                 `json:"enable" form:"enable" gorm:"index:idx_enable_traffic_reset,priority:1"`                           // Whether the inbound is enabled
	ExpiryTime           int64                `json:"expiryTime" form:"expiryTime"`                                                                    // Expiration timestamp
	TrafficReset         string               `json:"trafficReset" form:"trafficReset" gorm:"default:never;index:idx_enable_traffic_reset,priority:2"` // Traffic reset schedule
	LastTrafficResetTime int64                `json:"lastTrafficResetTime" form:"lastTrafficResetTime" gorm:"default:0"`                               // Last traffic reset timestamp
	ClientStats          []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`                        // Client traffic statistics

	// Traffic Multiplier: weight a client's usage once they pass a threshold. Below
	// TrafficMultiplierAfter traffic counts 1:1; past it each byte counts
	// TrafficMultiplier times against the client's quota. Applies to every protocol.
	// The multiplier defaults to 1 (not 0) so existing rows keep counting 1:1.
	TrafficMultiplierEnable bool    `json:"trafficMultiplierEnable" form:"trafficMultiplierEnable" gorm:"default:0"` // Whether the multiplier applies
	TrafficMultiplierAfter  int64   `json:"trafficMultiplierAfter" form:"trafficMultiplierAfter" gorm:"default:0"`   // Threshold in bytes, counted on up+down
	TrafficMultiplier       float64 `json:"trafficMultiplier" form:"trafficMultiplier" gorm:"default:1"`             // Weight applied past the threshold

	// Speed Limit: throttle each account on this inbound to a fixed rate. Configured
	// per inbound but ENFORCED PER EMAIL: every account gets its OWN bucket at this
	// rate, so this is not a shared pool for the inbound. Applies to every protocol
	// (native Xray and the VPN ones alike) because the enforcement point is Xray's
	// dispatcher, which sits downstream of every inbound.
	//
	// These are columns rather than keys in Settings on purpose. Settings is passed
	// VERBATIM to Xray for native protocols (see GenXrayInboundConfig below), and only
	// settings["clients"] is rewritten on the way out, so a top-level key here would
	// leak into Xray's own config. Columns also give every protocol one shared form
	// instead of a copy per protocol.
	//
	// Rates are KB/s (1 KB = 1024 B) to match the UI. They are converted to bytes/s in
	// exactly one place, where the limiter sidecar is written, so the 1024-vs-1000
	// question lives there and nowhere else. 0 in a direction means that direction is
	// unlimited.
	SpeedLimitEnable   bool  `json:"speedLimitEnable" form:"speedLimitEnable" gorm:"default:0"`     // Whether the limiter applies
	SpeedLimitSeparate bool  `json:"speedLimitSeparate" form:"speedLimitSeparate" gorm:"default:0"` // false = SpeedLimitDown caps BOTH directions
	SpeedLimitDown     int   `json:"speedLimitDown" form:"speedLimitDown" gorm:"default:0"`         // KB/s, 0 = unlimited
	SpeedLimitUp       int   `json:"speedLimitUp" form:"speedLimitUp" gorm:"default:0"`             // KB/s, 0 = unlimited; unused when SpeedLimitSeparate is false
	SpeedLimitAfter    int64 `json:"speedLimitAfter" form:"speedLimitAfter" gorm:"default:0"`       // Threshold in bytes on up+down; 0 = apply immediately

	// Xray configuration fields
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`
}

// OutboundTraffics tracks traffic statistics for Xray outbound connections.
type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

// InboundClientIps stores IP addresses associated with inbound clients for access control.
type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

// HistoryOfSeeders tracks which database seeders have been executed to prevent re-running.
type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

// GenXrayInboundConfig generates an Xray inbound configuration from the Inbound model.
func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	// Default to 0.0.0.0 (all interfaces) when listen is empty
	// This ensures proper dual-stack IPv4/IPv6 binding in systems where bindv6only=0
	if listen == "" {
		listen = "0.0.0.0"
	}
	listen = fmt.Sprintf("\"%v\"", listen)
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

// Setting stores key-value configuration settings for the vpn-ui panel.
type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type CustomGeoResource struct {
	Id            int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Type          string `json:"type" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias;column:geo_type"`
	Alias         string `json:"alias" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias"`
	Url           string `json:"url" gorm:"not null"`
	LocalPath     string `json:"localPath" gorm:"column:local_path"`
	LastUpdatedAt int64  `json:"lastUpdatedAt" gorm:"default:0;column:last_updated_at"`
	LastModified  string `json:"lastModified" gorm:"column:last_modified"`
	CreatedAt     int64  `json:"createdAt" gorm:"autoCreateTime;column:created_at"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime;column:updated_at"`
}

// Client represents a client configuration for Xray inbounds with traffic limits and settings.
type Client struct {
	ID         string `json:"id,omitempty"`                 // Unique client identifier
	Security   string `json:"security"`                     // Security method (e.g., "auto", "aes-128-gcm")
	Password   string `json:"password,omitempty"`           // Client password
	Flow       string `json:"flow,omitempty"`               // Flow control (XTLS)
	Auth       string `json:"auth,omitempty"`               // Auth password (Hysteria)
	Email      string `json:"email"`                        // Client email identifier
	LimitIP    int    `json:"limitIp"`                      // IP limit for this client
	TotalGB    int64  `json:"totalGB" form:"totalGB"`       // Total traffic limit in GB
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"` // Expiration timestamp
	Enable     bool   `json:"enable" form:"enable"`         // Whether the client is enabled
	TgID       int64  `json:"tgId" form:"tgId"`             // Telegram user ID for notifications
	SubID      string `json:"subId" form:"subId"`           // Subscription identifier
	Comment    string `json:"comment" form:"comment"`       // Client comment
	Reset      int    `json:"reset" form:"reset"`           // Reset period in days

	// MTProto Proxy per-account settings. Every client posted to the panel is
	// normalized through THIS struct, so a field missing here is silently dropped no
	// matter what the UI sent: which for mtproto means an account with no secret and
	// no modes, filtered out of the generated config, leaving the daemon refusing to
	// start with "No users configured". All are omitempty so no other protocol's
	// client JSON grows a single byte.
	Secret        string                `json:"secret,omitempty"`        // 32-hex credential (identity is Email)
	ModeClassic   bool                  `json:"modeClassic,omitempty"`   // accept this account's bare secret
	ModeSecure    bool                  `json:"modeSecure,omitempty"`    // accept its "dd" secret
	ModeTls       bool                  `json:"modeTls,omitempty"`       // accept its "ee" (FakeTLS) secret
	TlsDomain     string                `json:"tlsDomain,omitempty"`     // SNI its FakeTLS link fronts
	AdtagEnable   bool                  `json:"adtagEnable,omitempty"`   // credit sponsored channels to Adtag
	Adtag         string                `json:"adtag,omitempty"`         // 32 hex from @MTProxybot
	UserLimit     *int                  `json:"userLimit,omitempty"`     // max devices (distinct IPs); nil=absent, 0=no limit
	ExternalProxy []ClientExternalProxy `json:"externalProxy,omitempty"` // alternate link endpoints (links only)

	CreatedAt int64 `json:"created_at,omitempty"` // Creation timestamp
	UpdatedAt int64 `json:"updated_at,omitempty"` // Last update timestamp
}
