// Package backend bundles the VPN daemon binaries (xl2tpd, and later
// openvpn/libreswan/pppd) directly into the vpn-ui executable via go:embed and
// extracts them at runtime. This lets the panel "bake in" the backend instead
// of installing daemons per-distro through the host package manager.
//
// The bundled binaries are built statically against musl (see
// build/backend/build.sh) so they run on any Linux distribution regardless of
// its libc — including minimal cloud images. Kernel modules are still a host
// concern (they can't be bundled); those are handled by the provisioning step.
package backend

import (
	"embed"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
)

// bundleFS holds the per-architecture daemon binaries. The `all:` prefix keeps
// the embed working when only the .gitkeep placeholder is present (a checkout
// without the prebuilt binaries still compiles — Extract simply becomes a no-op).
//
//go:embed all:bin
var bundleFS embed.FS

// Daemon describes one bundled daemon.
type Daemon struct {
	Name string // binary file name, e.g. "xl2tpd"
}

// Daemons is the manifest of bundled daemons (extended as more are added).
var Daemons = []Daemon{
	{Name: "xl2tpd"},
	{Name: "xl2tpd-control"},
	{Name: "openvpn"},
	{Name: "pptpd"},
	{Name: "pptpctrl"},
	{Name: "ocserv"},
	{Name: "ocserv-worker"},
	{Name: "occtl"},
	// telemt (MTProto Proxy) is a single fully-static musl binary with no plugins to
	// dlopen and no fixed install path, so it belongs in this flat manifest rather
	// than needing a relocatable tree bundle like accel-ppp/strongSwan.
	{Name: "telemt"},
}

// PptpCtrlLink is the fixed path pptpd was compiled to exec pptpctrl from
// (--sbindir sentinel). Provisioning symlinks it to the extracted pptpctrl so
// the bundle works regardless of where vpn-ui is installed.
const PptpCtrlLink = "/usr/libexec/vpn-ui/pptpctrl"

// archDir is the embedded sub-directory for the running architecture.
func archDir() string { return "bin/" + runtime.GOARCH }

// Available reports whether a daemon bundle is embedded for this architecture.
func Available() bool {
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			return true
		}
	}
	return false
}

// BinDir is the absolute directory where daemons are extracted. It is the SAME
// "bin" folder the Xray core uses (config.GetBinFolderPath()), so every backend
// file lands flat in bin/ with no sub-folder — resolved next to the vpn-ui
// executable, so it adapts to any install location (/usr/local/vpn-ui,
// /usr/lib/vpn-ui, …). An absolute VPNUI_BIN_FOLDER is honored as-is.
func BinDir() string {
	bin := config.GetBinFolderPath()
	if filepath.IsAbs(bin) {
		return bin
	}
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("/usr/local/vpn-ui", bin)
	}
	return filepath.Join(filepath.Dir(exe), bin)
}

// DaemonPath returns the extracted path of a bundled daemon if it exists on
// disk, otherwise "".
func DaemonPath(name string) string {
	p := filepath.Join(BinDir(), name)
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return p
	}
	return ""
}

// Extract writes all bundled daemon binaries for this architecture into BinDir()
// with 0755 permissions. It is idempotent (overwrites existing files) and a
// no-op when no bundle is embedded. Returns the list of files written.
func Extract() ([]string, error) { return extract(nil) }

// ExtractOnly writes just the named bundled daemons. Names are binary file names
// as listed in Daemons, e.g. "xl2tpd". A name with no matching embedded file is
// skipped silently: bundles are per-architecture, so asking for a daemon this
// build does not ship is a normal outcome, not an error.
//
// An EMPTY list extracts nothing, which is the only safe reading of "extract
// only these". It deliberately does NOT mean "everything" (use Extract for
// that): the cores with no daemon of their own (SSTP, IKEv2, WireGuard,
// AmneziaWG) ask for an empty set on every install, and an empty-means-all
// contract silently laid down the entire bundle for them, which is exactly the
// thing per-core setup exists to prevent.
//
// The selective form exists because "installed" is decided by the binary being
// on disk (DaemonPath / daemonInstalled), so extracting everything would make
// every core report itself installed no matter which ones the operator picked.
func ExtractOnly(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	return extract(names)
}

// extract writes the bundled daemons for this architecture into BinDir with 0755
// permissions. A nil `names` means every daemon in the bundle. It is idempotent
// (overwrites existing files) and a no-op when no bundle is embedded.
func extract(names []string) ([]string, error) {
	if !Available() {
		return nil, nil
	}
	var want map[string]bool
	if names != nil {
		want = make(map[string]bool, len(names))
		for _, n := range names {
			want[n] = true
		}
	}
	dir := BinDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	entries, err := bundleFS.ReadDir(archDir())
	if err != nil {
		return nil, err
	}
	var written []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		// Archive bundles (e.g. the pppd tree) are extracted separately, not
		// dropped as a flat file into BinDir.
		if strings.HasSuffix(e.Name(), ".tgz") {
			continue
		}
		if want != nil && !want[e.Name()] {
			continue
		}
		data, err := bundleFS.ReadFile(archDir() + "/" + e.Name())
		if err != nil {
			return written, err
		}
		dest := filepath.Join(dir, e.Name())
		if err := writeExecutable(dest, data); err != nil {
			return written, err
		}
		written = append(written, dest)
	}
	return written, nil
}

// RemoveDaemons deletes the named extracted daemon binaries from BinDir. It is
// the inverse of ExtractOnly, used when a core is uninstalled; an absent file
// is not an error. Returns the paths actually removed.
func RemoveDaemons(names []string) ([]string, error) {
	dir := BinDir()
	var removed []string
	var firstErr error
	for _, n := range names {
		if n == "" || strings.ContainsAny(n, "/\\") {
			continue // only ever flat names inside BinDir
		}
		p := filepath.Join(dir, n)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := os.Remove(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed = append(removed, p)
	}
	return removed, firstErr
}

// writeExecutable writes an executable to dest via a temp file + atomic rename.
// A plain overwrite of a daemon that's currently running fails with ETXTBSY
// ("text file busy") because the kernel keeps the running binary's file mapped.
// Rename swaps the directory entry to a fresh inode instead — the running
// process keeps executing the old inode, and the next start picks up the new one.
func writeExecutable(dest string, data []byte) error {
	return WriteFileAtomic(dest, data, 0o755)
}

// WriteFileAtomic writes data to dest via a temp file + atomic rename, the same
// way writeExecutable does, but for any mode: bundle trees carry 0755 binaries
// next to 0644 configs and dictionaries.
//
// Every file a live daemon holds must be replaced this way, not just the ELF the
// wrapper names. A bundle's entry point execs the musl loader (lib/ld-musl-*.so.1)
// with the real binary as an argument, so the loader is what the kernel marks
// busy, so overwriting it in place is what raises ETXTBSY on a setup re-run. The
// .so and .bin files are worse: the kernel permits overwriting those under a live
// daemon, silently corrupting its mmap'd pages until it segfaults. Rename avoids
// both: the running process keeps the old inode and the next start gets the new one.
func WriteFileAtomic(dest string, data []byte, mode os.FileMode) error {
	tmp := dest + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		// O_CREATE|O_TRUNC happens before the write, so a failure part-way through
		// (ENOSPC, EIO, RLIMIT_FSIZE) leaves a partial file behind.
		_ = os.Remove(tmp)
		return err
	}
	// os.WriteFile applies the umask on create, so set the mode explicitly.
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// extractRegularFile writes one tar entry to target, atomically.
func extractRegularFile(target string, tr io.Reader, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return err
	}
	return WriteFileAtomic(target, data, mode)
}
