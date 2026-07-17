package service

import (
	"bytes"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
)

const kb = 1024

// limited builds an enabled per-inbound limiter policy. separate=false leaves up
// unread, matching the UI's single-box mode.
func limited(separate bool, down, up int, after int64) *model.Inbound {
	return &model.Inbound{
		SpeedLimitEnable:   true,
		SpeedLimitSeparate: separate,
		SpeedLimitDown:     down,
		SpeedLimitUp:       up,
		SpeedLimitAfter:    after,
	}
}

// pol covers one email with one inbound's policy.
func pol(inb *model.Inbound, emails ...string) speedLimitPolicy {
	return speedLimitPolicy{inbound: inb, emails: emails}
}

// find returns the published entry for email, or nil when the account is absent
// (which is how "unlimited" is expressed on the wire).
func find(users []speedLimitUser, email string) *speedLimitUser {
	for i := range users {
		if users[i].Email == email {
			return &users[i]
		}
	}
	return nil
}

func TestComputeSpeedLimits(t *testing.T) {
	tests := []struct {
		name     string
		policies []speedLimitPolicy
		usage    map[string]int64
		// wantAbsent asserts the account is unlimited (absent from the file).
		wantAbsent       bool
		wantDown, wantUp int64
	}{
		// Off / no-op cases: nothing to publish.
		{"limiter disabled", []speedLimitPolicy{pol(&model.Inbound{SpeedLimitDown: 100}, "a")}, nil, true, 0, 0},
		{"enabled but both rates zero", []speedLimitPolicy{pol(limited(true, 0, 0, 0), "a")}, nil, true, 0, 0},
		{"no policies at all", nil, nil, true, 0, 0},

		// separate=false: the single box caps EACH direction at that value. It is not a
		// combined bucket, and SpeedLimitUp is not read.
		{"combined mirrors down onto up", []speedLimitPolicy{pol(limited(false, 640, 0, 0), "a")}, nil, false, 640 * kb, 640 * kb},
		{"combined ignores the up field", []speedLimitPolicy{pol(limited(false, 640, 999, 0), "a")}, nil, false, 640 * kb, 640 * kb},

		// separate=true: the two directions are independent, including the asymmetric
		// states a single box cannot express.
		{"separate keeps directions independent", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, nil, false, 640 * kb, 256 * kb},
		{"separate down only", []speedLimitPolicy{pol(limited(true, 640, 0, 0), "a")}, nil, false, 640 * kb, 0},
		{"separate up only", []speedLimitPolicy{pol(limited(true, 0, 256, 0), "a")}, nil, false, 0, 256 * kb},

		// Limit After: below the threshold the account is not yet armed, so it must be
		// absent (unlimited), and armed at or above it.
		{"usage below threshold is unarmed", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": gb - 1}, true, 0, 0},
		{"usage at threshold arms", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": gb}, false, 640 * kb, 256 * kb},
		{"usage above threshold arms", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, map[string]int64{"a": 5 * gb}, false, 640 * kb, 256 * kb},
		{"no usage row is unarmed", []speedLimitPolicy{pol(limited(true, 640, 256, gb), "a")}, nil, true, 0, 0},
		// Threshold 0 (the column default) applies from the very first byte.
		{"zero threshold applies immediately", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, nil, false, 640 * kb, 256 * kb},
		{"zero threshold with zero usage", []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a")}, map[string]int64{"a": 0}, false, 640 * kb, 256 * kb},

		// One email on two inbounds: minimum non-zero wins, per direction.
		{
			"min wins across two inbounds",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 512, 0), "a")},
			nil, false, 320 * kb, 256 * kb,
		},
		// 0 means unlimited, so it must LOSE the min against a real rate. A plain min()
		// would return 0 here and silently unlimit an account the other inbound limits.
		{
			"unlimited direction does not win the min",
			[]speedLimitPolicy{pol(limited(true, 640, 0, 0), "a"), pol(limited(true, 0, 256, 0), "a")},
			nil, false, 640 * kb, 256 * kb,
		},
		{
			"zero loses the min in both orders",
			[]speedLimitPolicy{pol(limited(true, 0, 256, 0), "a"), pol(limited(true, 640, 0, 0), "a")},
			nil, false, 640 * kb, 256 * kb,
		},
		// An inbound below its own threshold contributes nothing, so it must not unlimit
		// an account that an armed inbound limits. Same rule as above, different route.
		{
			"unarmed inbound does not unlimit an armed one",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 128, gb), "a")},
			map[string]int64{"a": 0}, false, 640 * kb, 256 * kb,
		},
		{
			"both armed takes the stricter",
			[]speedLimitPolicy{pol(limited(true, 640, 256, 0), "a"), pol(limited(true, 320, 128, gb), "a")},
			map[string]int64{"a": 2 * gb}, false, 320 * kb, 128 * kb,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := find(computeSpeedLimits(tc.policies, tc.usage, nil), "a")
			if tc.wantAbsent {
				if got != nil {
					t.Fatalf("account is unlimited but was published as %+v; it must be absent", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want down=%d up=%d; account absent from output", tc.wantDown, tc.wantUp)
			}
			if got.DownBps != tc.wantDown || got.UpBps != tc.wantUp {
				t.Errorf("got down=%d up=%d; want down=%d up=%d", got.DownBps, got.UpBps, tc.wantDown, tc.wantUp)
			}
		})
	}
}

// The UI is KB/s and the wire is bytes/s. 1 KB = 1024 B, decided once, here.
func TestSpeedLimitUsesBinaryKB(t *testing.T) {
	users := computeSpeedLimits([]speedLimitPolicy{pol(limited(true, 1, 1000, 0), "a")}, nil, nil)
	got := find(users, "a")
	if got == nil {
		t.Fatal("account absent")
	}
	if got.DownBps != 1024 {
		t.Errorf("1 KB/s = %d B/s; want 1024 (binary KB, not 1000)", got.DownBps)
	}
	if got.UpBps != 1024000 {
		t.Errorf("1000 KB/s = %d B/s; want 1024000", got.UpBps)
	}
}

// Only limited accounts are published: an unlimited one must not cost the core a
// bucket, and the file must not name it at all.
func TestSpeedLimitOmitsUnlimitedAccounts(t *testing.T) {
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 256, 0), "limited@x"),
		pol(limited(true, 640, 256, gb), "unarmed@x"),     // below threshold
		pol(&model.Inbound{SpeedLimitDown: 640}, "off@x"), // limiter switched off
		pol(limited(true, 0, 0, 0), "enabled-but-zero@x"), // enabled, no rates
	}
	users := computeSpeedLimits(policies, map[string]int64{"unarmed@x": 1}, nil)
	if len(users) != 1 {
		t.Fatalf("published %d users (%+v); want only the limited one", len(users), users)
	}
	if users[0].Email != "limited@x" {
		t.Errorf("published %q; want limited@x", users[0].Email)
	}
}

// The email->IP index only ever indexes onto the email, which is the real bucket key.
func TestSpeedLimitIPs(t *testing.T) {
	ipMap := map[string][]string{
		// The ppp-family paths hand back bare addresses, unsorted, and OpenVPN can repeat
		// one per enabled transport. The block paths (ikev2 psk/eap-tls, wg-c) hand back
		// a CIDR already.
		"ppp@x":   {"10.2.0.7", "10.2.0.5", "10.2.0.5"},
		"block@x": {"10.6.0.0/24"},
	}
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 0, 0), "ppp@x", "block@x", "relay@x"),
	}
	users := computeSpeedLimits(policies, nil, ipMap)

	want := map[string][]string{
		// Bare addresses widen to host routes so the core parses one shape.
		"ppp@x":   {"10.2.0.5/32", "10.2.0.7/32"},
		"block@x": {"10.6.0.0/24"},
		// ssh/mtproto/native carry the email on the session itself, so they are published
		// with no addresses rather than not published at all.
		"relay@x": {},
	}
	for email, wantIPs := range want {
		got := find(users, email)
		if got == nil {
			t.Fatalf("%s absent from output", email)
		}
		if got.IPs == nil {
			t.Errorf("%s: ips is nil; it must serialize as [], not null", email)
		}
		if len(got.IPs) != len(wantIPs) {
			t.Fatalf("%s: ips = %v; want %v", email, got.IPs, wantIPs)
		}
		for i := range wantIPs {
			if got.IPs[i] != wantIPs[i] {
				t.Errorf("%s: ips = %v; want %v (sorted, deduplicated)", email, got.IPs, wantIPs)
			}
		}
	}
}

// The writer skips the write when the bytes match, so identical input MUST render
// identical bytes. Map iteration order is randomized per run, so without the sorts
// this fails and the core reloads its rate table every 10s forever.
func TestSpeedLimitDocumentIsDeterministic(t *testing.T) {
	policies := []speedLimitPolicy{
		pol(limited(true, 640, 256, 0), "c@x", "a@x", "b@x"),
		pol(limited(false, 320, 0, 0), "e@x", "d@x"),
	}
	ipMap := map[string][]string{
		"a@x": {"10.2.0.9", "10.2.0.3", "10.2.0.6"},
		"b@x": {"10.6.0.0/24"},
	}
	usage := map[string]int64{"a@x": 5 * gb, "b@x": 1}

	first, err := speedLimitDocument(policies, usage, ipMap)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := speedLimitDocument(policies, usage, ipMap)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("run %d differs from run 1; the output must be byte-identical\nfirst:\n%s\nagain:\n%s", i+2, first, again)
		}
	}
}

// The sidecar's schema is a contract with the patched core: field names, field order,
// bytes/s, and [] rather than null for an account with no addresses.
func TestSpeedLimitDocumentShape(t *testing.T) {
	policies := []speedLimitPolicy{pol(limited(true, 640, 256, 0), "a@x")}
	ipMap := map[string][]string{"a@x": {"10.0.0.5"}}

	got, err := speedLimitDocument(policies, nil, ipMap)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "users": [
    {
      "email": "a@x",
      "downBps": 655360,
      "upBps": 262144,
      "ips": [
        "10.0.0.5/32"
      ]
    }
  ]
}
`
	if string(got) != want {
		t.Errorf("sidecar shape drifted\ngot:\n%s\nwant:\n%s", got, want)
	}
}

// With nothing limited the file is an empty user list, NOT an absent or null one: it
// has to be able to tell the core that the last limit was removed.
func TestSpeedLimitDocumentEmpty(t *testing.T) {
	got, err := speedLimitDocument(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"users\": []\n}\n"
	if string(got) != want {
		t.Errorf("empty document = %q; want %q", got, want)
	}
}
