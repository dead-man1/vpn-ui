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
	AWG         Protocol = "awg"
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

	// Permissions is the capability bitmask; ignored for a super admin, and
	// ignored for a reseller (whose mask is derived from the role, see Can).
	Permissions Permission `json:"-" gorm:"default:0"`

	// IsReseller marks an account that sells VPN accounts out of a traffic
	// balance. It is a ROLE and not a permission bit because it changes which
	// objects exist for the account rather than what it may do to them: a
	// reseller sees only the clients it created, even on an inbound it shares
	// with an admin. A mask cannot express that.
	//
	// Never true at the same time as IsSuperAdmin; ResellerService enforces it.
	// The quota levers live in ResellerProfile, one row per reseller, so this
	// table (read on EVERY request by session.loadLoginUser) stays narrow.
	IsReseller bool `json:"isReseller" gorm:"default:0"`

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

// ResellerProfile holds one reseller's balance and the levers an admin sets on
// them. Split from User because these fields are meaningless for every admin
// row, and because the balance is written under transaction on every account
// create/edit/delete: keeping those writes off the row that every request reads
// is worth one join on the rare page that needs it.
type ResellerProfile struct {
	Id     int `json:"id" gorm:"primaryKey;autoIncrement"`
	UserId int `json:"userId" gorm:"uniqueIndex"`

	// AllowanceBytes is the cumulative traffic an admin has granted. SpentBytes
	// is what is currently committed to live accounts plus what past accounts
	// burned before being deleted. Available = Allowance - Spent.
	//
	// BYTES, never GB. Client.TotalGB is a byte count despite its name (see
	// web/assets/js/model/inbound.js _totalGB, which divides by ONE_GB purely
	// for display), and a unit mismatch on this pair is free traffic.
	AllowanceBytes int64 `json:"allowanceBytes" gorm:"default:0"`
	SpentBytes     int64 `json:"spentBytes" gorm:"default:0"`
	// Unlimited skips the balance CHECK but not the accrual: SpentBytes keeps
	// climbing, so an admin who later sets a limit correctly accounts for what
	// this reseller already sold. Stored explicitly rather than overloading
	// AllowanceBytes==0, so that an admin who leaves the field blank while
	// creating a reseller does not silently mint an unlimited one.
	Unlimited bool `json:"unlimited" gorm:"default:0"`

	// DaysPerGB > 0 FORCES an account's duration: expiry is GB * DaysPerGB, and
	// the reseller gets no expiry field at all. 0 leaves the choice to them.
	DaysPerGB int `json:"daysPerGb" gorm:"default:0"`
	// MinCreateGB is the smallest account they may create, MinAddGB the smallest
	// top-up in one edit. Whole GB, as an operator sets them; 0 means no floor.
	MinCreateGB int `json:"minCreateGb" gorm:"default:0"`
	MinAddGB    int `json:"minAddGb" gorm:"default:0"`

	// AllowExternalProxy lets the configs and links this reseller generates carry
	// the inbound's external-proxy endpoints. Off strips them.
	AllowExternalProxy bool `json:"allowExternalProxy" gorm:"default:0"`

	// AllowOverview lets this reseller open the panel overview. Off (the default)
	// hides the nav entry entirely rather than greying it, and the page itself
	// redirects: the overview is a HOST dashboard (kernel, CPU, disk, public IP)
	// and none of it is a reseller's to see unless an operator says otherwise.
	AllowOverview bool `json:"allowOverview" gorm:"default:0"`

	// CreatedBy is the admin who owns this reseller. A non-super admin holding
	// PermManageResellers sees and edits only their own: without this, one such
	// admin could edit another's reseller balance or reassign their inbounds.
	CreatedBy int `json:"createdBy" gorm:"index"`
}

// ResellerClient records that a reseller owns an account, and what that account
// currently costs them. Ownership and charge are one row because they are 1:1
// on the account, so two tables would only be two things to keep in sync.
//
// ABSENCE of a row means the house owns the account. Admins and super admins
// have no balance, so there is nothing to charge and their paths need no ledger
// awareness at all.
type ResellerClient struct {
	Id int `json:"id" gorm:"primaryKey;autoIncrement"`
	// Email is the panel-wide account identity. xray.ClientTraffic.Email carries
	// gorm:"unique", and AdminService.CanAccessClientEmail already keys on it, so
	// this matches the seam that exists rather than inventing a second notion of
	// "which client".
	Email     string `json:"email" gorm:"uniqueIndex"`
	InboundId int    `json:"inboundId" gorm:"index"`
	UserId    int    `json:"userId" gorm:"index"`

	// ChargedBytes is what this account currently holds against its reseller's
	// balance: raised on create and top-up, lowered on deduct and delete.
	ChargedBytes int64 `json:"chargedBytes" gorm:"default:0"`
	// AllTimeBase is ClientTraffic.AllTime at the moment of the charge, so
	// consumption is measured from the charge and not from the account's whole
	// life. AllTime is used rather than Up+Down because it is monotonic across a
	// traffic reset (see web/service/traffic_accounting_test.go), which is what
	// stops a reset from turning consumed bytes back into a refundable balance.
	AllTimeBase int64 `json:"allTimeBase" gorm:"default:0"`
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

	// IP Limit: the DEFAULT cap on how many distinct client source addresses ONE account
	// on this inbound may hold at once. 0 = no limit.
	//
	// Client.LimitIP (below, and long predating this) overrides it per client, so this is
	// the operator's baseline for the whole inbound rather than a second, competing cap:
	// see resolveIPLimit for the resolution, including why a client-level 0 inherits this
	// default instead of forcing "unlimited".
	//
	// It counts ADDRESSES, not devices: devices behind one NAT share one source address
	// and count as one. That undercount is irreducible rather than a defect (see
	// ip-limiter-plan.md), which is exactly why the name says IP and must keep saying IP.
	IPLimit int `json:"ipLimit" form:"ipLimit" gorm:"default:0"`

	// IP Limit Strategy: what happens when an account already at its IP Limit is seen
	// from a NEW source address. "reject" (the default) refuses the newcomer; "accept"
	// admits it and disconnects that account's oldest address.
	//
	// The words are the VPN User Limit's ("accept"/"reject", see normUserLimitStrategy)
	// on purpose: this is the same question asked at a different enforcement point, and
	// a synonym here would make the three points look like three features.
	//
	// Unlike the cap above, this has NO per-client override, and the asymmetry is
	// deliberate: how many addresses an account may hold is that account's entitlement, so
	// a client may carry its own, but what to do AT the cap is the operator's policy for
	// the whole inbound and not something an individual account should have a say in.
	//
	// A column rather than a key in Settings for the same reason as the SpeedLimit* block
	// above: Settings is passed VERBATIM to Xray for native protocols and only
	// settings["clients"] is rewritten on the way out, so a top-level key there would leak
	// into Xray's own config. AutoMigrate adds the column, and the gorm default is what
	// makes every pre-existing row read back "reject" instead of "" (readers normalize the
	// empty string to reject anyway, so the default is belt-and-braces, not the contract).
	IPLimitStrategy string `json:"ipLimitStrategy" form:"ipLimitStrategy" gorm:"default:reject"`

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
