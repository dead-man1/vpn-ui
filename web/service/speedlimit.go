package service

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/backend"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Speed Limit: publish each account's effective rate to the patched Xray core.
//
// The policy is configured PER INBOUND but enforced PER EMAIL, because email is the
// account identity everywhere downstream (the unique key of client_traffics, the name
// RADIUS authenticates, the selector the per-account routing rules are built from).
// So every account on a limited inbound gets its OWN bucket at that rate: this is not
// a shared pool for the inbound, and an account's K devices share one bucket.
//
// The panel decides, Xray obeys. "Limit After" is resolved HERE against the usage the
// panel already tracks, and the core receives only the already-resolved rate. That
// keeps quota semantics (resets, VPN usage sourced from nft/RADIUS rather than Xray's
// own stats) in the one place that understands them, and keeps the fork patch small
// enough to rebase on every core bump.
//
// The delivery path is a sidecar file, NOT the Xray config. A rate change must not
// touch anything in the xray.Config graph: Config.Equals would report a change and the
// debounced restart would drop every live connection on the box, and threshold
// crossings happen continuously as users consume data. For the same reason nothing
// here calls SetToNeedRestart.

// speedLimitUser is one account's published rate. Field order is fixed by this struct
// and the values are BYTES PER SECOND; 0 in a direction means that direction is
// unlimited. An account that is unlimited in BOTH directions is absent from the file
// entirely, so the core's common-case hot path is one map miss.
type speedLimitUser struct {
	Email   string   `json:"email"`
	DownBps int64    `json:"downBps"`
	UpBps   int64    `json:"upBps"`
	IPs     []string `json:"ips"`
}

// speedLimitDoc is the sidecar's whole schema.
type speedLimitDoc struct {
	Users []speedLimitUser `json:"users"`
}

// speedLimitPolicy pairs one inbound's limiter columns with the emails it covers.
// Splitting this out of the DB read is what lets the resolution below be tested as a
// pure function, with no SQLite and no Settings JSON.
type speedLimitPolicy struct {
	inbound *model.Inbound
	emails  []string
}

// bytesPerKB is the ONLY place the 1024-vs-1000 question exists. The UI speaks KB/s,
// every internal value and the sidecar speak bytes/s, and the conversion happens here
// once so no other site has to know which convention it is holding.
const bytesPerKB = 1024

// kbpsToBps converts a UI KB/s rate to bytes/s. Negative rates cannot arrive through
// the panel, but this is the last line of defence for a row that came some other way
// (an imported DB, a hand-edited SQLite file): a negative rate published to the core
// would be a negative token bucket limit, which is not "unlimited", it is "stalled".
func kbpsToBps(kbps int) int64 {
	if kbps <= 0 {
		return 0
	}
	return int64(kbps) * bytesPerKB
}

// inboundSpeedLimitRates resolves one inbound's columns into a candidate (down, up)
// pair in bytes/s, before "Limit After" is considered.
//
// SpeedLimitSeparate false means the single UI box caps EACH direction independently
// at that value, so the down value is mirrored onto up. It does NOT mean a combined
// up+down bucket, and SpeedLimitUp is not read at all in that mode. Mirroring here
// keeps the wire format one shape, so the core never learns the mode exists.
func inboundSpeedLimitRates(inb *model.Inbound) (down, up int64) {
	if inb == nil || !inb.SpeedLimitEnable {
		return 0, 0
	}
	down = kbpsToBps(inb.SpeedLimitDown)
	if inb.SpeedLimitSeparate {
		return down, kbpsToBps(inb.SpeedLimitUp)
	}
	return down, down
}

// speedLimitArmed reports whether an account with the given cumulative usage has
// passed inb's "Limit After" threshold.
//
// This is deliberately STATELESS: it re-derives the answer from the stored counter on
// every run rather than latching a flag. That is what makes the limit re-arm by itself
// whenever up/down are zeroed, no matter which path did the zeroing (the per-client
// reset field, the periodic reset job, an admin's manual reset). A latched flag would
// leave an account throttled after its quota was restored.
func speedLimitArmed(inb *model.Inbound, usage int64) bool {
	// 0 means apply from the very first byte, and is also the column default, so the
	// >= below already covers it. Spelled out because "0 = immediately" is a contract.
	return usage >= inb.SpeedLimitAfter
}

// minNonZeroRate merges two candidate rates for one direction, most restrictive wins.
//
// The whole subtlety of the feature is here. 0 means UNLIMITED, not "zero bytes per
// second", so a plain min() would let an unlimited inbound silently unlimit an account
// that a second inbound limits. 0 must therefore lose to any real rate, and win only
// against another 0.
func minNonZeroRate(a, b int64) int64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

// normalizeSpeedLimitIP renders one BuildVpnEmailToIPMap value as a CIDR.
//
// That map mixes shapes: the ppp-family paths yield a bare address ("10.2.0.5") while
// the ikev2 psk/eap-tls and wg-c paths yield a block ("10.6.0.0/24"), because those
// two model an account as a whole block rather than K owned addresses. The core indexes
// these into one prefix trie, so widening the bare addresses to host routes here keeps
// the file to a single shape and the trie to a single parse.
func normalizeSpeedLimitIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.Contains(v, "/") {
		return v
	}
	ip := net.ParseIP(v)
	if ip == nil {
		return v
	}
	if ip.To4() != nil {
		return v + "/32"
	}
	return v + "/128"
}

// speedLimitIPs returns email's tunnel addresses as a sorted, deduplicated CIDR list.
// Never nil: an account with no addresses must still serialize as an empty JSON array,
// see computeSpeedLimits.
func speedLimitIPs(email string, ipMap map[string][]string) []string {
	raw := ipMap[email]
	out := make([]string, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, v := range raw {
		v = normalizeSpeedLimitIP(v)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// computeSpeedLimits resolves every policy into the accounts' published rates.
//
// usage is cumulative up+down per email, and ipMap is BuildVpnEmailToIPMap's output.
// The result is sorted by email, with each user's ips sorted, because the output is
// compared byte-for-byte against the file on disk (see WriteSpeedLimits): map order
// alone would make every tick look like a change.
func computeSpeedLimits(policies []speedLimitPolicy, usage map[string]int64, ipMap map[string][]string) []speedLimitUser {
	type rates struct{ down, up int64 }
	merged := make(map[string]rates)

	for _, p := range policies {
		down, up := inboundSpeedLimitRates(p.inbound)
		if down == 0 && up == 0 {
			continue // enabled but unlimited in both directions: nothing to contribute
		}
		for _, email := range p.emails {
			if email == "" {
				continue
			}
			// Below the threshold this inbound contributes NOTHING rather than
			// contributing "unlimited". The difference matters when the same email sits
			// on two inbounds: a not-yet-armed inbound must not unlimit an account that
			// an armed one limits, which is the same 0-loses-the-min rule as below.
			if !speedLimitArmed(p.inbound, usage[email]) {
				continue
			}
			m := merged[email]
			// Same email on several inbounds: minimum non-zero wins, per direction and
			// independently. The bucket is per email, so per-(email, inbound) rates would
			// hand a user on two inbounds twice their intended bandwidth.
			merged[email] = rates{
				down: minNonZeroRate(m.down, down),
				up:   minNonZeroRate(m.up, up),
			}
		}
	}

	users := make([]speedLimitUser, 0, len(merged))
	for email, r := range merged {
		if r.down == 0 && r.up == 0 {
			continue // fully unlimited: absent from the file, so the core allocates nothing
		}
		users = append(users, speedLimitUser{
			Email:   email,
			DownBps: r.down,
			UpBps:   r.up,
			// Accounts with no addresses (ssh, mtproto, native Xray) still belong here:
			// their email arrives on the session itself, so they never touch the trie.
			IPs: speedLimitIPs(email, ipMap),
		})
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
	return users
}

// speedLimitDocument renders the policies as the sidecar's bytes. Deterministic for a
// given input: identical input must produce identical bytes, which is what lets the
// writer skip unchanged ticks.
func speedLimitDocument(policies []speedLimitPolicy, usage map[string]int64, ipMap map[string][]string) ([]byte, error) {
	doc := speedLimitDoc{Users: computeSpeedLimits(policies, usage, ipMap)}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// loadSpeedLimitPolicies reads the limited inbounds and the emails they cover.
//
// The WHERE clause is what makes this affordable on the 10s tick: with the feature off
// nowhere it returns no rows, and no Settings blob is ever unmarshalled. Disabled
// inbounds are excluded because they pass no traffic to shape.
func loadSpeedLimitPolicies() []speedLimitPolicy {
	db := database.GetDB()
	if db == nil {
		return nil
	}
	var inbounds []*model.Inbound
	err := db.Model(model.Inbound{}).
		Where("enable = ? AND speed_limit_enable = ?", true, true).
		Find(&inbounds).Error
	if err != nil {
		logger.Warning("speed limit: load inbounds failed:", err)
		return nil
	}

	// Decoded locally, and to emails only, rather than through InboundService.GetClients:
	// every protocol stores its accounts under settings.clients with an email, so this
	// needs no per-protocol knowledge and pulls in no service.
	type clientEntry struct {
		Email string `json:"email"`
	}
	type settingsJSON struct {
		Clients []clientEntry `json:"clients"`
	}

	policies := make([]speedLimitPolicy, 0, len(inbounds))
	for _, inbound := range inbounds {
		var settings settingsJSON
		if err := json.Unmarshal([]byte(inbound.Settings), &settings); err != nil {
			continue
		}
		emails := make([]string, 0, len(settings.Clients))
		for _, c := range settings.Clients {
			if strings.TrimSpace(c.Email) == "" {
				continue
			}
			// The email is used verbatim, NOT trimmed or folded: it has to match the key
			// BuildVpnEmailToIPMap and client_traffics use, and those are the stored
			// string. Normalization belongs on write (see normalizeClientEmails), not here.
			emails = append(emails, c.Email)
		}
		policies = append(policies, speedLimitPolicy{inbound: inbound, emails: emails})
	}
	return policies
}

// loadSpeedLimitUsage returns cumulative up+down per email.
//
// This is the same counter the quota enforcer reads, so "Limit After" and totalGB
// measure the same bytes, including the traffic multiplier's weighting.
func loadSpeedLimitUsage() map[string]int64 {
	usage := make(map[string]int64)
	db := database.GetDB()
	if db == nil {
		return usage
	}
	var rows []xray.ClientTraffic
	err := db.Model(xray.ClientTraffic{}).Select("email", "up", "down").Find(&rows).Error
	if err != nil {
		logger.Warning("speed limit: load usage failed:", err)
		return usage
	}
	for _, r := range rows {
		usage[r.Email] = r.Up + r.Down
	}
	return usage
}

// WriteSpeedLimits recomputes every account's effective rate and republishes the
// sidecar. Safe to call on every traffic tick.
//
// Write ONLY on change. The core watches this file's mtime, and a write bumps mtime
// whether or not the bytes differ, so an unconditional write would make it reload every
// 10s forever and would defeat the deterministic ordering above, which exists precisely
// so the common (nothing changed) tick is byte-identical. MTProto's config writer hit
// exactly this and documents it at generateServerConfig.
//
// The write is atomic (temp + rename) because the reader is a live process polling the
// path: a plain overwrite lets it catch a half-written document and parse-fail, which
// on a rate table means either no limits or stale ones until the next change.
func WriteSpeedLimits() {
	policies := loadSpeedLimitPolicies()
	var usage map[string]int64
	var ipMap map[string][]string
	// With no inbound limited, the document is empty whatever the usage and addresses
	// are, so neither is loaded. That keeps the feature's cost on an operator who does
	// not use it (the common case) to one query returning no rows per tick, instead of
	// a full client_traffics scan plus an email->IP index rebuild.
	if len(policies) > 0 {
		usage = loadSpeedLimitUsage()
		ipMap = BuildVpnEmailToIPMap()
	}
	data, err := speedLimitDocument(policies, usage, ipMap)
	if err != nil {
		logger.Warning("speed limit: marshal failed:", err)
		return
	}
	path := xray.GetSpeedLimitPath()
	if old, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(old, data) {
		return
	}
	// 0600: the file names every limited account. Nothing but the panel writes it and
	// nothing but Xray (running as the same user) reads it.
	if err := backend.WriteFileAtomic(path, data, 0o600); err != nil {
		logger.Warning("speed limit: write", path, "failed:", err)
	}
}
