#!/usr/bin/env bash
# MmD
set -euo pipefail

REPO="Sir-MmD/vpn-ui"
ASSET="vpn-ui-amd64"
DEST_DIR="/opt/vpn-ui"
DEST="$DEST_DIR/$ASSET"
UNIT="vpn-ui"
DL_URL="https://github.com/$REPO/releases/latest/download/$ASSET"
# The panel keeps its SQLite DB next to the binary (exe dir). Backups go beside it.
DB="$DEST_DIR/vpn-ui.db"
BACKUP_DIR="$DEST_DIR/backups"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    B=$'\e[1m'; D=$'\e[2m'; R=$'\e[0m'
    BLUE=$'\e[38;5;39m'; GREEN=$'\e[38;5;114m'; RED=$'\e[38;5;203m'
    YELLOW=$'\e[38;5;221m'; TEAL=$'\e[38;5;44m'; WHITE=$'\e[1;38;5;255m'
else
    B= D= R= BLUE= GREEN= RED= YELLOW= TEAL= WHITE=
fi

# ":: text"  bold-blue header + bold-white message (pacman's step style)
msg()  { printf '%s::%s %s%s%s\n' "$B$BLUE" "$R" "$WHITE" "$*" "$R"; }
# "  -> text"  blue action arrow
act()  { printf '  %s->%s %s\n' "$BLUE" "$R" "$*"; }
ok()   { printf '  %s->%s %s%s%s\n' "$GREEN" "$R" "$GREEN" "$*" "$R"; }
warn() { printf '%swarning:%s %s\n' "$B$YELLOW" "$R" "$*" >&2; }
die()  { printf '%serror:%s %s\n'   "$B$RED" "$R" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$D" "$(printf '%.0s-' {1..60})" "$R"; }

# Acquire root: re-exec through sudo when not already root, so `./deploy.sh`
# just works. If invoked piped (no script file) or without sudo, bail with
# instructions instead of failing obscurely.
if [[ $EUID -ne 0 ]]; then
    if [[ -f "$0" ]] && command -v sudo >/dev/null 2>&1; then
        exec sudo -- bash "$0" "$@"
    fi
    die "must run as root — use: sudo $0   (piped: curl -fsSL <url> | sudo bash)"
fi

# Preflight
hr
printf '%s[%sVPN-UI%s]%s deploy\n' "$B$TEAL" "$GREEN" "$TEAL" "$R"
hr

command -v systemctl >/dev/null 2>&1 || die "systemctl not found — this host isn't running systemd."

arch="$(uname -m)"
[[ "$arch" == "x86_64" || "$arch" == "amd64" ]] || \
    warn "host architecture is '$arch' — this installs the amd64 build, which may not run here."

# Fresh install vs in-place update: an already-installed binary means UPDATE. On
# update we must NOT re-randomize credentials (that would lock the operator out of
# their own panel) and we snapshot the DB before the new binary can migrate it.
MODE="install"; OLD_VER=""
if [[ -e "$DEST" ]]; then
    MODE="update"
    OLD_VER="$("$DEST" -v 2>/dev/null | tr -d '[:space:]')"
fi

if   command -v curl >/dev/null 2>&1; then DL="curl"
elif command -v wget >/dev/null 2>&1; then DL="wget"
else die "need 'curl' or 'wget' to download the release."; fi

# Resolve + download the latest release asset
msg "Fetching latest release of $REPO"

# Best-effort: read the release tag from the /releases/latest redirect (display only).
ver=""
if [[ "$DL" == "curl" ]]; then
    ver="$(curl -sILo /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" 2>/dev/null \
           | grep -oE 'tag/[^/[:space:]]+$' | sed 's#tag/##' || true)"
fi
[[ -n "$ver" ]] && act "latest release: ${GREEN}${ver}${R}" || act "asset: ${GREEN}${ASSET}${R}"
if [[ "$MODE" == "update" ]]; then
    act "mode:   ${YELLOW}update${R} (${OLD_VER:-unknown} -> ${ver:-latest})"
else
    act "mode:   ${GREEN}fresh install${R}"
fi

install -d -m 0755 "$DEST_DIR"
tmp="$(mktemp "${DEST}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

msg "Downloading ${ASSET}"
if [[ "$DL" == "curl" ]]; then
    curl -fL --retry 3 --progress-bar -o "$tmp" "$DL_URL" \
        || die "download failed from $DL_URL — is there a published release with a '$ASSET' asset?"
else
    wget --tries=3 --show-progress -qO "$tmp" "$DL_URL" \
        || die "download failed from $DL_URL — is there a published release with a '$ASSET' asset?"
fi

# Sanity: non-empty and a real Linux ELF binary (not an HTML 404 page).
[[ -s "$tmp" ]] || die "downloaded file is empty."
if command -v file >/dev/null 2>&1; then
    file -b "$tmp" | grep -qi 'ELF' || die "downloaded file is not an ELF binary (got: $(file -b "$tmp"))."
else
    [[ "$(head -c4 "$tmp")" == $'\x7fELF' ]] || die "downloaded file is not an ELF binary."
fi
ok "downloaded $(du -h "$tmp" | cut -f1)"

# Install the binary (stop the unit first if we're upgrading in place)
if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    act "stopping running ${UNIT} for replacement"
    systemctl stop "$UNIT" || true
fi

# Safety net: on update, snapshot the DB (timestamped + tagged with the outgoing
# version) before the new binary can touch or migrate it. The service is already
# stopped above, so copy the SQLite WAL/SHM sidecars alongside it for a consistent
# set. Abort if the copy fails — never replace the binary without a good backup.
if [[ "$MODE" == "update" && -f "$DB" ]]; then
    install -d -m 0755 "$BACKUP_DIR"
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="$BACKUP_DIR/vpn-ui_${OLD_VER:-unknown}_${ts}.db"
    cp -p "$DB" "$backup" || die "DB backup failed ($DB -> $backup) — aborting before replacing the binary."
    for side in wal shm; do
        [[ -f "$DB-$side" ]] && cp -p "$DB-$side" "$backup-$side" || true
    done
    ok "backed up DB -> $backup"
fi

chmod +x "$tmp"
mv -f "$tmp" "$DEST"
trap - EXIT
ok "installed -> $DEST"

# Configure + install/refresh the systemd unit. Fresh installs get randomized
# credentials (--random); updates DO NOT, so the operator's existing port, login
# and web path survive the upgrade.
if [[ "$MODE" == "install" ]]; then
    msg "Configuring credentials + installing systemd unit"
    warn "--random sets a fresh port, username, password and web path — note them below."
    "$DEST" --random --systemd
else
    msg "Refreshing systemd unit (existing credentials preserved)"
    "$DEST" --systemd
fi

msg "Starting ${UNIT}"
systemctl restart "$UNIT"
sleep 1
if systemctl is-active --quiet "$UNIT"; then
    ok "${UNIT} is running"
else
    die "${UNIT} failed to start — inspect with: journalctl -u ${UNIT} -e"
fi

# Done
hr
msg "Deploy complete"
if [[ "$MODE" == "install" ]]; then
    act "the randomized login (port / user / password / web path) is printed above ${B}↑${R}"
else
    act "updated to ${GREEN}${ver:-latest}${R} — your existing port / login / web path are unchanged"
    [[ -n "${backup:-}" ]] && act "DB backup: ${TEAL}${backup}${R}"
fi
act "status:  ${TEAL}systemctl status ${UNIT}${R}"
act "logs:    ${TEAL}journalctl -u ${UNIT} -f${R}"
hr
