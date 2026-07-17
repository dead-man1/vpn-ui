package xray

// ClientTraffic represents traffic statistics and limits for a specific client.
// It tracks upload/download usage, expiry times, and online status for inbound clients.
type ClientTraffic struct {
	Id        int  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	InboundId int  `json:"inboundId" form:"inboundId"`
	Enable    bool `json:"enable" form:"enable"`
	// Email is the global account identity, unique across ALL inbounds (see the email
	// helpers in web/service/inbound.go). This index is the last line of defense, not
	// a formality: ImportDB (web/service/server.go) swaps the SQLite file wholesale
	// and so bypasses every service-level check, leaving the constraint as the only
	// thing standing between a hand-edited backup and two clients sharing an identity.
	Email      string `json:"email" form:"email" gorm:"unique"`
	UUID       string `json:"uuid" form:"uuid" gorm:"-"`
	SubId      string `json:"subId" form:"subId" gorm:"-"`
	Up         int64  `json:"up" form:"up"`
	Down       int64  `json:"down" form:"down"`
	AllTime    int64  `json:"allTime" form:"allTime"`
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"`
	Total      int64  `json:"total" form:"total"`
	Reset      int    `json:"reset" form:"reset" gorm:"default:0"`
	LastOnline int64  `json:"lastOnline" form:"lastOnline" gorm:"default:0"`
}
