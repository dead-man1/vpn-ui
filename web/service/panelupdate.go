package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// panelUpdateInFlight guards against a second UpdatePanel running concurrently
// (e.g. a proxy 504 makes the browser retry while the first is still downloading),
// which would race on the ".new" temp path and the binary swap.
var panelUpdateInFlight atomic.Bool

// Panel self-update. The panel binary ships as a single GitHub release asset
// (Sir-MmD/vpn-ui, "vpn-ui-amd64") — the same source deploy.sh installs from — so
// the overview can both check for and apply updates in place.
const (
	panelRepo        = "Sir-MmD/vpn-ui"
	panelAsset       = "vpn-ui-amd64"
	panelLatestAPI   = "https://api.github.com/repos/" + panelRepo + "/releases/latest"
	panelDownloadURL = "https://github.com/" + panelRepo + "/releases/latest/download/" + panelAsset
)

// PanelUpdateInfo reports the running version vs. the latest published release.
type PanelUpdateInfo struct {
	Current   string `json:"current"`
	Latest    string `json:"latest"`
	Available bool   `json:"available"`
}

// CheckPanelUpdate queries GitHub for the latest release tag and compares it to
// the running version. Best-effort and short-timeout: it runs on every overview
// load, so a slow/unreachable GitHub must not hang the dashboard.
func (s *ServerService) CheckPanelUpdate() (*PanelUpdateInfo, error) {
	cur := config.GetVersion()
	info := &PanelUpdateInfo{Current: cur, Latest: cur}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, panelLatestAPI, nil)
	if err != nil {
		return info, err
	}
	req.Header.Set("User-Agent", "vpn-ui") // GitHub API rejects requests without a UA
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return info, err
	}
	var rel Release
	if err := json.Unmarshal(body, &rel); err != nil {
		return info, err
	}

	latest := strings.TrimPrefix(strings.TrimSpace(rel.TagName), "v")
	if latest != "" {
		info.Latest = latest
	}
	info.Available = versionNewer(latest, cur)
	return info, nil
}

// UpdatePanel downloads the latest release binary, snapshots the DB, atomically
// replaces the running executable, and restarts the panel so the new binary takes
// over. Replacing a running ELF via rename is safe on Linux: the live process keeps
// the old (now-unlinked) inode, and the next start execs the new file.
func (s *ServerService) UpdatePanel() error {
	if !panelUpdateInFlight.CompareAndSwap(false, true) {
		return fmt.Errorf("a panel update is already in progress")
	}
	// Reset the guard on every early/error return. On success we intentionally leave
	// it set: restartPanel is about to replace this process, so the in-memory flag
	// dies with it (and blocks a duplicate update during the restart window).
	restarting := false
	defer func() {
		if !restarting {
			panelUpdateInFlight.Store(false)
		}
	}()

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve own path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	tmp := exe + ".new"
	logger.Infof("panel update: downloading %s", panelDownloadURL)
	if err := downloadPanelBinary(tmp, panelDownloadURL); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Validate it's an ELF for THIS architecture — a 404 HTML page, a truncated
	// file, or a wrong-arch asset would otherwise be renamed over the running binary
	// and brick the panel (the restart would fail with exec-format-error).
	if !isCompatibleBinary(tmp) {
		_ = os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a %s Linux binary (no valid '%s' asset?)", runtime.GOARCH, panelAsset)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	// Best-effort DB snapshot before the new binary can migrate it.
	backupPanelDB()

	// Keep a copy of the current binary next to it so a bad update can be rolled
	// back manually (mv vpn-ui.bak vpn-ui): once renamed, the old inode is gone.
	if err := copyFileBestEffort(exe, exe+".bak"); err == nil {
		_ = os.Chmod(exe+".bak", 0o755)
	} else {
		logger.Warning("panel update: binary backup failed (continuing):", err)
	}

	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replacing binary failed: %w", err)
	}
	logger.Infof("panel update: installed new binary at %s — restarting", exe)

	// Restart detached so our own termination can't abort the restart.
	restarting = true
	go restartPanel(exe)
	return nil
}

// downloadPanelBinary streams url into dst (0755).
func downloadPanelBinary(dst, url string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "vpn-ui")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, url)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return err
	}
	return nil
}

// elfMachineFor maps a GOARCH to its ELF e_machine value (little-endian targets
// only). The bool is false for archs we don't map, in which case only the ELF magic
// is checked (still catches an HTML 404 page, just not a wrong-arch binary).
func elfMachineFor(goarch string) (uint16, bool) {
	switch goarch {
	case "amd64":
		return 0x3E, true // EM_X86_64
	case "arm64":
		return 0xB7, true // EM_AARCH64
	case "386":
		return 0x03, true // EM_386
	case "arm":
		return 0x28, true // EM_ARM
	}
	return 0, false
}

// isCompatibleBinary reports whether path is an ELF whose architecture matches the
// running panel. Guards against installing an HTML error page, a truncated file, or
// a wrong-architecture asset over the live binary (which would brick the restart).
func isCompatibleBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var hdr [20]byte // magic(4) + ident(12) + e_type(2) + e_machine(2)
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	if hdr[0] != 0x7f || hdr[1] != 'E' || hdr[2] != 'L' || hdr[3] != 'F' {
		return false
	}
	if hdr[5] != 1 { // EI_DATA: only little-endian targets are supported
		return false
	}
	machine := uint16(hdr[18]) | uint16(hdr[19])<<8
	if want, ok := elfMachineFor(runtime.GOARCH); ok && machine != want {
		return false
	}
	return true
}

// backupPanelDB copies the SQLite DB (and its WAL/SHM sidecars) next to it with a
// versioned name. Best-effort — a failed snapshot must not block the update.
func backupPanelDB() {
	db := config.GetDBPath()
	if _, err := os.Stat(db); err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(db), "backups")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	// Fold the WAL into the main DB first so the file copy is a consistent snapshot
	// (the panel holds the DB open, so a plain copy could otherwise be torn).
	if gdb := database.GetDB(); gdb != nil {
		if sqlDB, err := gdb.DB(); err == nil {
			_, _ = sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		}
	}
	base := fmt.Sprintf("vpn-ui_%s.db", config.GetVersion())
	dst := filepath.Join(dir, base)
	if err := copyFileBestEffort(db, dst); err != nil {
		logger.Warning("panel update: DB backup failed:", err)
		return
	}
	for _, side := range []string{"-wal", "-shm"} {
		_ = copyFileBestEffort(db+side, dst+side)
	}
	logger.Infof("panel update: backed up DB -> %s", dst)
}

func copyFileBestEffort(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// restartPanel brings the new binary online. Under systemd (the deploy.sh setup)
// it triggers a detached `systemctl restart` that survives this process's death;
// otherwise it re-execs the freshly installed binary in place.
func restartPanel(exe string) {
	time.Sleep(1 * time.Second) // give the HTTP response time to flush
	var sd SystemdService
	name := sd.GetServiceName()
	if commandExists("systemctl") && systemctlActive(name) {
		// setsid detaches the restarter so systemd killing us mid-restart is fine.
		if err := exec.Command("setsid", "sh", "-c", fmt.Sprintf("sleep 1; systemctl restart %s", name)).Start(); err != nil {
			// The restart never launched: the binary is already swapped but this
			// process keeps running the old one. Release the guard so the operator
			// can retry from the panel (or restart the unit manually).
			logger.Warning("panel update: failed to launch restarter — retry the update or restart the unit manually:", err)
			panelUpdateInFlight.Store(false)
		}
		return
	}
	// No systemd: re-exec the new binary, replacing this process image.
	if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
		logger.Warning("panel update: re-exec failed, exiting for supervisor restart:", err)
		os.Exit(0)
	}
}

// versionNewer reports whether dotted version a is strictly newer than b (both
// may carry a leading "v"). Non-numeric or unparseable tags yield false, so a
// malformed release never spuriously advertises an update.
func versionNewer(a, b string) bool {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	if a == "" {
		return false
	}
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			return x > y
		}
	}
	return false
}
