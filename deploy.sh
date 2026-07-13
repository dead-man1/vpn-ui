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
# Real-SSL (Let's Encrypt via acme.sh, standalone HTTP-01). DEPLOY_DOMAIN /
# DEPLOY_EMAIL preset these for a non-interactive issuance; otherwise prompted.
CERT_DIR="$DEST_DIR/cert"
DOMAIN="${DEPLOY_DOMAIN:-}"
EMAIL="${DEPLOY_EMAIL:-}"

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

# Obtain a REAL certificate (Let's Encrypt via acme.sh, standalone HTTP-01) and
# point the panel's HTTPS at it. Needs a public DNS A record for $DOMAIN pointing
# at this host and TCP :80 free during issuance. The same cert files can be reused
# for SSTP so stock Windows trusts it. Best-effort: on any failure it warns and
# leaves the panel's current TLS untouched (returns non-zero). Callers guard with
# `|| ...` so set -e is suspended inside — unguarded failures won't abort deploy.
obtain_letsencrypt_cert() {
    if [[ -z "$DOMAIN" && -r /dev/tty ]]; then
        printf '  %sdomain%s (DNS A record must point here): ' "$BLUE" "$R" > /dev/tty
        read -r DOMAIN < /dev/tty || DOMAIN=""
    fi
    [[ -n "$DOMAIN" ]] || { warn "no domain (set DEPLOY_DOMAIN=…) — skipping real SSL."; return 1; }
    if [[ -z "$EMAIL" && -r /dev/tty ]]; then
        printf "  %semail%s (Let's Encrypt account, optional): " "$BLUE" "$R" > /dev/tty
        read -r EMAIL < /dev/tty || EMAIL=""
    fi

    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
        { warn "need curl or wget for acme.sh — skipping real SSL."; return 1; }

    # acme.sh standalone binds :80. Warn (don't fail) if it's already taken.
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ':80$'; then
        warn "TCP :80 is in use — acme.sh standalone may fail to bind it."
    fi

    local ACME="$HOME/.acme.sh/acme.sh"
    if ! [[ -x "$ACME" ]]; then
        if command -v acme.sh >/dev/null 2>&1; then
            ACME="$(command -v acme.sh)"
        else
            msg "Installing acme.sh"
            if command -v curl >/dev/null 2>&1; then
                curl -fsSL https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}" >/dev/null 2>&1 \
                    || { warn "acme.sh install failed — skipping real SSL."; return 1; }
            else
                wget -qO- https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}" >/dev/null 2>&1 \
                    || { warn "acme.sh install failed — skipping real SSL."; return 1; }
            fi
            ACME="$HOME/.acme.sh/acme.sh"
        fi
    fi
    [[ -x "$ACME" ]] || { warn "acme.sh not found after install — skipping real SSL."; return 1; }

    "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    msg "Issuing Let's Encrypt certificate for ${DOMAIN} (standalone HTTP-01)"
    # RSA-2048 for the widest client trust (legacy Windows SSTP included).
    if ! "$ACME" --issue -d "$DOMAIN" --standalone --keylength 2048; then
        # acme returns non-zero when an existing cert is still valid ("skip"); only
        # bail when no cert directory was produced at all.
        if [[ ! -d "$HOME/.acme.sh/${DOMAIN}" && ! -d "$HOME/.acme.sh/${DOMAIN}_ecc" ]]; then
            warn "acme.sh issuance failed for ${DOMAIN} — check the DNS A record and that :80 is reachable."
            return 1
        fi
    fi

    install -d -m 0755 "$CERT_DIR"
    msg "Installing certificate + auto-renew hook"
    # `|| true` on the reload: acme runs reloadcmd immediately, but on a FRESH
    # install the systemd unit doesn't exist yet (it's created later by --systemd),
    # so a bare `systemctl restart` would fail and make install-cert return non-zero.
    # The tolerant form still restarts correctly on future auto-renewals.
    "$ACME" --install-cert -d "$DOMAIN" \
        --key-file       "$CERT_DIR/privkey.pem" \
        --fullchain-file "$CERT_DIR/fullchain.pem" \
        --reloadcmd      "systemctl restart $UNIT || true" \
        || { warn "acme.sh install-cert failed — skipping real SSL."; return 1; }

    # Point the panel's web server (and subscription server) at the real cert.
    "$DEST" cert -webCert "$CERT_DIR/fullchain.pem" -webCertKey "$CERT_DIR/privkey.pem" >/dev/null 2>&1 \
        || { warn "applying cert to panel failed."; return 1; }
    ok "real certificate installed for ${DOMAIN}"
    return 0
}

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
    # Panel transport: HTTP (default) or self-signed HTTPS. Honour PANEL_TLS when
    # preset (selfsign/https -> TLS; http -> plain); otherwise ask on the
    # controlling terminal. A piped, non-interactive install with no PANEL_TLS set
    # falls back to HTTP so `curl ... | sudo bash` never hangs on a prompt.
    tls_choice="http"
    case "${PANEL_TLS:-}" in
        letsencrypt|le|acme|real)        tls_choice="letsencrypt" ;;
        selfsign|https|self-signed|yes)  tls_choice="selfsign" ;;
        http|plain|0|no)                 tls_choice="http" ;;
        "")
            # A preset DEPLOY_DOMAIN implies a non-interactive real-cert request.
            if [[ -n "$DOMAIN" ]]; then
                tls_choice="letsencrypt"
            elif [[ -r /dev/tty ]]; then
                {
                    printf '%s::%s %sPanel access mode%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
                    printf "    %s1)%s HTTPS  (real cert via Let's Encrypt / acme.sh)\n" "$GREEN" "$R"
                    printf '    %s2)%s HTTPS  (self-signed certificate)\n'                "$GREEN" "$R"
                    printf '    %s3)%s HTTP   (no TLS) %s[default]%s\n'                    "$GREEN" "$R" "$D" "$R"
                    printf '  choose [1/2/3]: '
                } > /dev/tty
                read -r _ans < /dev/tty || _ans=""
                case "$_ans" in
                    1) tls_choice="letsencrypt" ;;
                    2) tls_choice="selfsign" ;;
                esac
            fi
            ;;
        *) warn "unrecognized PANEL_TLS='${PANEL_TLS}' — defaulting to HTTP." ;;
    esac

    # Enable the chosen cert BEFORE --random so the randomized run sees the TLS
    # setting and prints an https:// URL. A failed Let's Encrypt attempt falls back
    # to plain HTTP rather than aborting the whole install.
    if [[ "$tls_choice" == "selfsign" ]]; then
        msg "Generating self-signed TLS certificate (HTTPS)"
        "$DEST" cert -selfsign
    elif [[ "$tls_choice" == "letsencrypt" ]]; then
        obtain_letsencrypt_cert || tls_choice="http"
    fi

    # Panel login / access: randomize everything (default) or enter custom values.
    # Ask on the controlling terminal; a piped, non-interactive install (curl ... |
    # sudo bash) has no tty and falls back to --random, so it never hangs on the
    # prompt nor installs empty credentials. The binary applies either choice with
    # the same work-safe stop/apply/restart envelope (--random / --user...--path).
    cred_mode="random"
    if [[ -r /dev/tty ]]; then
        {
            printf '%s::%s %sPanel login / access%s\n' "$B$BLUE" "$R" "$WHITE" "$R"
            printf '    %s1)%s Randomize  (port, username, password, web path) %s[default]%s\n' "$GREEN" "$R" "$D" "$R"
            printf '    %s2)%s Custom     (enter each value yourself)\n' "$GREEN" "$R"
            printf '  choose [1/2]: '
        } > /dev/tty
        read -r _cans < /dev/tty || _cans=""
        [[ "$_cans" == "2" ]] && cred_mode="custom"
    fi

    if [[ "$cred_mode" == "custom" ]]; then
        msg "Enter panel login / access details (leave a field blank to keep the default)"
        printf '  %susername%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_USER < /dev/tty || C_USER=""
        printf '  %spassword%s: ' "$BLUE" "$R" > /dev/tty; read -rs C_PASS < /dev/tty || C_PASS=""; printf '\n' > /dev/tty
        printf '  %sport%s: '     "$BLUE" "$R" > /dev/tty; read -r  C_PORT < /dev/tty || C_PORT=""
        printf '  %sweb path%s: ' "$BLUE" "$R" > /dev/tty; read -r  C_PATH < /dev/tty || C_PATH=""
        msg "Applying custom login / access + installing systemd unit"
        "$DEST" --user "$C_USER" --pass "$C_PASS" --port "$C_PORT" --path "$C_PATH" --systemd
    else
        msg "Configuring credentials + installing systemd unit"
        warn "--random sets a fresh port, username, password and web path — note them below."
        "$DEST" --random --systemd
    fi
else
    # Update: only touch TLS when explicitly requested (PANEL_TLS=letsencrypt or a
    # DEPLOY_DOMAIN is set), so routine binary updates never change the transport.
    if [[ "${PANEL_TLS:-}" =~ ^(letsencrypt|le|acme|real)$ || -n "$DOMAIN" ]]; then
        obtain_letsencrypt_cert || true
    fi
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
    if [[ "${cred_mode:-random}" == "custom" ]]; then
        act "your custom login (port / user / password / web path) was applied — see above"
    else
        act "the randomized login (port / user / password / web path) is printed above"
    fi
    if [[ "${tls_choice:-http}" == "letsencrypt" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a real cert for ${TEAL}${DOMAIN}${R} — no browser warning"
        act "auto-renew runs via acme.sh (cron); SSTP can reuse ${TEAL}$CERT_DIR/fullchain.pem${R} + ${TEAL}$CERT_DIR/privkey.pem${R}"
    elif [[ "${tls_choice:-http}" == "selfsign" ]]; then
        act "panel serves ${GREEN}HTTPS${R} with a self-signed cert — the browser warns once; accept it to continue"
    fi
else
    act "updated to ${GREEN}${ver:-latest}${R} — your existing port / login / web path are unchanged"
    [[ -n "${backup:-}" ]] && act "DB backup: ${TEAL}${backup}${R}"
fi
act "status:  ${TEAL}systemctl status ${UNIT}${R}"
act "logs:    ${TEAL}journalctl -u ${UNIT} -f${R}"
hr
