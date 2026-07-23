package model

// Permission is a bitmask of what an admin may do, stored as an integer column on
// User. A super admin bypasses the mask entirely and is the only one who may
// manage other admins.
//
// The bitmask is a storage detail. Slugs (below) are what cross the wire to the
// API and the UI, so bits may be reordered freely but a slug rename is breaking.
type Permission int64

const (
	PermAccessInbounds Permission = 1 << iota
	PermCreateInbound
	PermEditInbound
	PermDeleteInbound
	PermCreateClient
	PermEditClient
	PermDeleteClient
	PermBulkOperation
	PermCoreSettings
	PermXraySettings
	PermPanelSettings
	// PermManageResellers gates the Resellers page and its API. APPENDED, never
	// inserted: the values are positional, so inserting a bit would shift every
	// mask already stored in the database by one.
	PermManageResellers
)

// resellerPerms is what a reseller may do, derived from the role rather than
// read from User.Permissions.
//
// Derived on purpose. A stored mask drifts: an ImportDB of a hand-edited backup,
// or one save path that forgets to clamp, leaves a reseller holding
// PermPanelSettings and nothing in the code notices. Deriving makes the role the
// single source of truth.
//
// Deliberately excludes every *Inbound bit: a reseller sells accounts on inbounds
// an admin assigned them, and creates none of its own.
//
// PermBulkOperation IS included, but it does not mean here what it means for an
// admin. The bulk routes are defined over "every client on this inbound", which
// for a reseller reaches accounts they do not own, so each one is separately
// scoped to their own accounts and priced against their balance
// (ResellerService.PrepareBulk). The two that cannot be scoped that way,
// resetAllTraffics and resetAllClientTraffics, stay refused in the controller.
// The bit is the door; it is not the authorization.
const resellerPerms = PermAccessInbounds | PermCreateClient | PermEditClient |
	PermDeleteClient | PermBulkOperation

// PermissionDef pairs a bit with its stable wire slug.
type PermissionDef struct {
	Bit  Permission `json:"-"`
	Slug string     `json:"slug"`
}

// AllPermissions is the canonical list, in the order the Admins UI renders it.
var AllPermissions = []PermissionDef{
	{PermAccessInbounds, "accessInbounds"},
	{PermCreateInbound, "createInbound"},
	{PermEditInbound, "editInbound"},
	{PermDeleteInbound, "deleteInbound"},
	{PermCreateClient, "createClient"},
	{PermEditClient, "editClient"},
	{PermDeleteClient, "deleteClient"},
	{PermBulkOperation, "bulkOperation"},
	{PermCoreSettings, "accessCoreSettings"},
	{PermXraySettings, "accessXraySettings"},
	{PermPanelSettings, "accessPanelSettings"},
	{PermManageResellers, "manageResellers"},
}

// Has reports whether every bit in q is set in p.
func (p Permission) Has(q Permission) bool { return p&q == q }

// Slugs expands the mask into its wire slugs, for the API and the UI.
func (p Permission) Slugs() []string {
	out := make([]string, 0, len(AllPermissions))
	for _, d := range AllPermissions {
		if p.Has(d.Bit) {
			out = append(out, d.Slug)
		}
	}
	return out
}

// PermissionsFromSlugs folds wire slugs back into a mask. Unknown slugs are
// ignored rather than erroring: a client sending a stale slug should lose that
// one permission, not have the whole save rejected.
func PermissionsFromSlugs(slugs []string) Permission {
	var p Permission
	for _, s := range slugs {
		for _, d := range AllPermissions {
			if d.Slug == s {
				p |= d.Bit
				break
			}
		}
	}
	return p
}

// Can reports whether the user may do perm. Super admins may do anything, which
// is why they are the only account type that can reach the escalation-class
// endpoints (DB export/import, panel update, systemd unit, host reboot).
func (u *User) Can(perm Permission) bool {
	if u == nil || !u.Enable {
		return false
	}
	if u.IsSuperAdmin {
		return true
	}
	// A reseller's stored mask is ignored entirely, so a stale or tampered
	// permissions column cannot widen the role.
	if u.IsReseller {
		return resellerPerms.Has(perm)
	}
	return u.Permissions.Has(perm)
}
