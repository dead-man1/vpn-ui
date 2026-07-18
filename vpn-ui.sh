#!/usr/bin/env bash
# MmD
#
# vpn-ui management menu: the `vpn-ui` command.
#
# Installed to /usr/bin/vpn-ui by `vpn-ui-amd64 install-menu`, which deploy.sh runs
# on every fresh install and update. The script is EMBEDDED in the binary it
# drives, so the two are always the same release: upstream installs its menu by
# curling raw.githubusercontent at `main`, which pins the default branch's tip even
# on a box running a tagged release, and leaves the menu's numbering describing a
# binary that isn't there.
#
# The script never scrapes the binary's human output (upstream's
# `x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}'` breaks the day
# someone rewords a line). Anything it only displays, the binary prints; anything
# it branches on comes from `vpn-ui-amd64 info --get <field>`, whose field names
# are a stable contract (see panelInfo in main.go). No jq required.
#
# It is also SOURCEABLE: deploy.sh sources this file purely to reuse
# obtain_letsencrypt_cert, so there is exactly ONE acme.sh implementation rather
# than two copies drifting apart. Everything below is a definition; the only code
# that runs is behind the sourced/executed guard at the very bottom. Keep it that
# way, or `source` will re-exec deploy.sh through sudo and drop it into a menu.
set -euo pipefail

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

# The panel binary this menu drives. VPNUI_BIN overrides it for a non-default
# install; deploy.sh exports it so the menu follows deploy.sh's own DEST.
BIN="${VPNUI_BIN:-/opt/vpn-ui/vpn-ui-amd64}"
# Every value below is preserved when already set, because deploy.sh sources this
# file with its own: sourcing must add the shared function, never quietly redefine
# the caller's configuration.
CERT_DIR="${CERT_DIR:-$(dirname "$BIN")/cert}"
DOMAIN="${DOMAIN:-${DEPLOY_DOMAIN:-}}"
EMAIL="${EMAIL:-${DEPLOY_EMAIL:-}}"

# --------------------------------------------------------------------------- #
#  Panel facts (never parsed out of prose)
# --------------------------------------------------------------------------- #

# Read one field of `vpn-ui-amd64 info --json` by name; prints the raw value.
# Tolerant of failure (empty output) so a caller under `set -e` can branch on it.
info_get() { "$BIN" info --get "$1" 2>/dev/null || true; }

# The panel's systemd unit. NEVER hardcode "vpn-ui": the name is operator
# configurable (settings key systemdServiceName, SystemdService.GetServiceName),
# and acting on the wrong unit is worse than not acting at all.
# Prints the unit name, or warns and returns non-zero. It deliberately does NOT
# die(): a die() inside the $(...) its callers use would only exit that subshell,
# leaving the caller to act on an EMPTY unit name (systemctl start "") while set -e
# decides the script's fate. Callers guard with `|| return 0` and stay in the menu.
panel_unit() {
    local u; u="$(info_get systemdUnit)"
    if [[ -z "$u" ]]; then
        warn "could not read the systemd unit name from '$BIN info'. Is the panel installed?"
        return 1
    fi
    printf '%s' "$u"
}

# True when a panel is alive but NOT under systemd.
#
# This is the production box's actual state: the panel is started by hand
# (setsid ./vpn-ui-amd64 &) with the unit inactive-but-enabled. systemd then
# reports the unit inactive while the panel is up and serving, so `systemctl stop`
# would exit 0 having stopped nothing, and `systemctl start` would launch a SECOND
# panel that collides on the web port and every inbound. The control socket is the
# only witness that cannot be fooled: only a live panel answers it.
panel_runs_unmanaged() {
    [[ "$(info_get systemdActive)" != "true" && "$(info_get panelRunning)" == "true" ]]
}

# Explain the unmanaged-panel state once, in the operator's words.
say_unmanaged() {
    warn "the unit '$1' is NOT active, yet a panel IS running (its control socket answers)."
    act  "it was started outside systemd (e.g. ${TEAL}setsid ./vpn-ui-amd64 &${R}), so systemd cannot manage it."
}

# --------------------------------------------------------------------------- #
#  Item 17: Get SSL  (shared with deploy.sh: one implementation, no copies)
# --------------------------------------------------------------------------- #

# Obtain a REAL certificate (Let's Encrypt via acme.sh, standalone HTTP-01) and
# point the panel's HTTPS at it. Needs a public DNS A record for $DOMAIN pointing
# at this host and TCP :80 free during issuance. The same cert files can be reused
# for SSTP so stock Windows trusts it. Best-effort: on any failure it warns and
# leaves the panel's current TLS untouched (returns non-zero). Callers guard with
# `|| ...` so set -e is suspended inside; unguarded failures won't abort deploy.
obtain_letsencrypt_cert() {
    if [[ -z "$DOMAIN" && -r /dev/tty ]]; then
        printf '  %sdomain%s (DNS A record must point here): ' "$BLUE" "$R" > /dev/tty
        read -r DOMAIN < /dev/tty || DOMAIN=""
    fi
    [[ -n "$DOMAIN" ]] || { warn "no domain (set DEPLOY_DOMAIN=...), skipping real SSL."; return 1; }
    if [[ -z "$EMAIL" && -r /dev/tty ]]; then
        printf "  %semail%s (Let's Encrypt account, optional): " "$BLUE" "$R" > /dev/tty
        read -r EMAIL < /dev/tty || EMAIL=""
    fi

    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || \
        { warn "need curl or wget for acme.sh, skipping real SSL."; return 1; }

    # acme.sh standalone binds :80. Warn (don't fail) if it's already taken.
    if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE ':80$'; then
        warn "TCP :80 is in use, acme.sh standalone may fail to bind it."
    fi

    # Ensure acme.sh's host prerequisites BEFORE touching it. Its `--install`
    # pre-check HARD-FAILS on a box with no cron daemon (minimal Fedora ships no
    # cronie), so the client never installs and real SSL silently drops to HTTP with
    # "acme.sh not found after install" — even though the box had internet. It also
    # needs socat or python for the standalone HTTP-01 server. The panel binary
    # installs both cross-distro (see EnsureAcmeDeps). No-op when already present;
    # best-effort, since --install --force below still issues without cron (only
    # auto-renew is lost). Guarded so a failure never aborts under the caller's set -e.
    msg "Ensuring acme.sh dependencies (cron + standalone server)"
    "$BIN" acme-deps 2>&1 | sed 's/^/  /' || true

    local ACME="$HOME/.acme.sh/acme.sh"
    if ! [[ -x "$ACME" ]]; then
        if command -v acme.sh >/dev/null 2>&1; then
            ACME="$(command -v acme.sh)"
        else
            # Install acme.sh from the copy BUNDLED in the panel binary. This is the
            # offline path: `curl https://get.acme.sh | sh` fails on a box with no or
            # blocked egress to get.acme.sh, which is exactly why real SSL was silently
            # skipped. The binary writes the pinned client into a scratch dir; running
            # it there as `--install` sets up $HOME/.acme.sh (account.conf, renew cron,
            # shell alias) with NO network fetch. Only `--issue` below needs the net,
            # and that reaches Let's Encrypt, not get.acme.sh. `--install` must run from
            # the dir holding the file literally named acme.sh: it does `cp acme.sh ...`.
            # --force: install even when no cron daemon is present (EnsureAcmeDeps could
            # not add one) so a locked-down host still gets its certificate; without it
            # the pre-check fails and issuance is skipped entirely.
            msg "Installing bundled acme.sh"
            local acmedir; acmedir="$(mktemp -d)"
            if "$BIN" install-acme "$acmedir/acme.sh" >/dev/null 2>&1 && [[ -s "$acmedir/acme.sh" ]]; then
                ( cd "$acmedir" && sh ./acme.sh --install --force -m "${EMAIL:-admin@$DOMAIN}" ) >/dev/null 2>&1 || true
            fi
            rm -rf "$acmedir"
            ACME="$HOME/.acme.sh/acme.sh"

            # Network fallback ONLY if the bundled install did not land (older binary
            # without `install-acme`, or a broken $HOME). Best-effort; issuance still
            # needs curl/wget, so requiring one here costs nothing extra.
            if ! [[ -x "$ACME" ]]; then
                msg "Bundled acme.sh unavailable, falling back to get.acme.sh"
                if command -v curl >/dev/null 2>&1; then
                    curl -fsSL https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}" >/dev/null 2>&1 || true
                elif command -v wget >/dev/null 2>&1; then
                    wget -qO- https://get.acme.sh | sh -s email="${EMAIL:-admin@$DOMAIN}" >/dev/null 2>&1 || true
                fi
                ACME="$HOME/.acme.sh/acme.sh"
            fi
        fi
    fi
    [[ -x "$ACME" ]] || { warn "acme.sh not found after install, skipping real SSL."; return 1; }

    "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

    msg "Issuing Let's Encrypt certificate for ${DOMAIN} (standalone HTTP-01)"
    # RSA-2048 for the widest client trust (legacy Windows SSTP included).
    if ! "$ACME" --issue -d "$DOMAIN" --standalone --keylength 2048; then
        # acme returns non-zero for two very different reasons and only one is fatal:
        #   - an existing cert is still valid ("skip") -> a real chain IS on disk, proceed;
        #   - issuance FAILED, e.g. the HTTP-01 check timed out because Let's Encrypt
        #     could not fetch the token over :80 (the domain doesn't point at THIS box,
        #     or :80 is firewalled/behind NAT) -> NO chain on disk, bail.
        # Gate on the actual fullchain, NOT the domain directory: acme.sh creates the
        # directory (with the domain key) even when validation fails, so its presence
        # proves nothing. Checking the dir let a failed issuance march into
        # --install-cert, which then died on a missing fullchain.cer and left a partial
        # key in $CERT_DIR.
        if [[ ! -s "$HOME/.acme.sh/${DOMAIN}/fullchain.cer" && ! -s "$HOME/.acme.sh/${DOMAIN}_ecc/fullchain.cer" ]]; then
            warn "acme.sh could not issue a certificate for ${DOMAIN}."
            warn "Let's Encrypt validates over HTTP: ${DOMAIN} must resolve to THIS server's public IP and TCP :80 must be reachable from the internet (not firewalled, not behind a proxy/CDN for a different host). The panel's TLS was left unchanged."
            return 1
        fi
    fi

    install -d -m 0755 "$CERT_DIR"
    msg "Installing certificate + auto-renew hook"
    # The unit is resolved, not assumed: an operator who renamed the panel's service
    # would otherwise get a renew hook that restarts a unit that does not exist.
    local unit; unit="$(info_get systemdUnit)"; [[ -n "$unit" ]] || unit="vpn-ui"
    # `|| true` on the reload: acme runs reloadcmd immediately, but on a FRESH
    # install the systemd unit doesn't exist yet (it's created later by --systemd),
    # so a bare `systemctl restart` would fail and make install-cert return non-zero.
    # The tolerant form still restarts correctly on future auto-renewals.
    "$ACME" --install-cert -d "$DOMAIN" \
        --key-file       "$CERT_DIR/privkey.pem" \
        --fullchain-file "$CERT_DIR/fullchain.pem" \
        --reloadcmd      "systemctl restart $unit || true" \
        || { warn "acme.sh install-cert failed, skipping real SSL."; return 1; }

    # Point the panel's web server (and subscription server) at the real cert.
    "$BIN" cert -webCert "$CERT_DIR/fullchain.pem" -webCertKey "$CERT_DIR/privkey.pem" >/dev/null 2>&1 \
        || { warn "applying cert to panel failed."; return 1; }
    ok "real certificate installed for ${DOMAIN}"
    return 0
}

# --------------------------------------------------------------------------- #
#  Menu items
# --------------------------------------------------------------------------- #

# 1) Update. The binary owns the whole flow (version check, DB backup, swap,
#    restart), including refreshing THIS script from the release it installs.
item_update() { "$BIN" update || warn "update did not complete."; }

# 2) Un-Install. The binary prompts for confirmation and removes /usr/bin/vpn-ui
#    (this file) among everything else, so there is no menu to return to.
item_uninstall() {
    "$BIN" --uninstall || { warn "uninstall did not complete."; return 0; }
    exit 0
}

# 3-6) Change username / password / port / web path. All four go through the
#      binary's work-safe switches, which stop the unit, apply, and start it again
#      (a live panel holds the DB open and would keep serving the old values).
item_username() {
    local v; printf '  %snew username%s: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no username entered, nothing changed."; return 0; }
    "$BIN" --user "$v" || warn "changing the username failed."
}

item_password() {
    local v; printf '  %snew password%s: ' "$BLUE" "$R"; read -rs v || return 0; printf '\n'
    [[ -n "$v" ]] || { warn "no password entered, nothing changed."; return 0; }
    "$BIN" --pass "$v" || warn "changing the password failed."
}

item_port() {
    local v; printf '  %snew port%s [1-65535]: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no port entered, nothing changed."; return 0; }
    if ! [[ "$v" =~ ^[0-9]+$ ]] || (( v < 1 || v > 65535 )); then
        warn "'$v' is not a valid port, nothing changed."
        return 0
    fi
    "$BIN" --port "$v" || warn "changing the port failed."
}

item_webpath() {
    local v; printf '  %snew web path%s: ' "$BLUE" "$R"; read -r v || return 0
    [[ -n "$v" ]] || { warn "no path entered, nothing changed."; return 0; }
    "$BIN" --path "$v" || warn "changing the web path failed."
}

# 7) Reset Login. Randomizes port, username, password AND web path, so the old
#    URL stops working too. Worth a confirmation.
item_random() {
    warn "this randomizes the port, username, password and web path. The current login stops working."
    local a; printf "  type %s'yes'%s to proceed: " "$WHITE" "$R"; read -r a || return 0
    [[ "$a" == "yes" ]] || { act "aborted, nothing changed."; return 0; }
    "$BIN" --random || warn "randomizing the login failed."
}

# 8) View current login info.
item_info() { "$BIN" info || warn "could not read the panel settings."; }

# 9-11) systemd start / stop / restart.
item_start() {
    local unit; unit="$(panel_unit)" || return 0
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "starting the unit now would run a SECOND panel that collides on the web port and every inbound."
        act  "stop the running one first, then start the unit."
        local a; printf '  start %s anyway? [y/N]: ' "$unit"; read -r a || return 0
        [[ "$a" == "y" || "$a" == "Y" ]] || { act "aborted."; return 0; }
    fi
    msg "Starting ${unit}"
    systemctl start "$unit" || { warn "systemctl start ${unit} failed. Inspect: journalctl -u ${unit} -e"; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

item_stop() {
    local unit; unit="$(panel_unit)" || return 0
    # Report the truth rather than a systemctl exit code: stopping an inactive unit
    # succeeds, which would look like "panel stopped" while it keeps serving.
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "'systemctl stop ${unit}' would report success and stop NOTHING. Not running it."
        act  "stop it by PID instead, e.g.:  ${TEAL}pkill -x $(basename "$BIN")${R}"
        act  "(never ${TEAL}pkill -f${R} a daemon name over SSH: the pattern matches your own shell)"
        return 0
    fi
    if [[ "$(info_get systemdActive)" != "true" ]]; then
        act "${unit} is already stopped, and no panel answers the control socket."
        return 0
    fi
    msg "Stopping ${unit}"
    systemctl stop "$unit" || { warn "systemctl stop ${unit} failed."; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

item_restart() {
    local unit; unit="$(panel_unit)" || return 0
    if panel_runs_unmanaged; then
        say_unmanaged "$unit"
        warn "'systemctl restart ${unit}' would not touch it, and would start a SECOND panel beside it."
        act  "stop the running one first, then restart the unit."
        return 0
    fi
    msg "Restarting ${unit}"
    systemctl restart "$unit" || { warn "systemctl restart ${unit} failed. Inspect: journalctl -u ${unit} -e"; return 0; }
    ok "${unit}: $(systemctl is-active "$unit" 2>/dev/null || true)"
}

# 12-14, 16) Xray + cores. These MUST go through the running panel: Xray and the
# VPN daemons are its child processes, tracked by in-process state, so a separate
# process acting on its own would report a running Xray as stopped and "restart" it
# into a second copy fighting for port 62790. `ctl` talks to the live panel and
# refuses (non-zero) when there is none. It never acts locally.
item_xray_start()   { "$BIN" ctl xray.start        || true; }
item_xray_stop()    { "$BIN" ctl xray.stop         || true; }
item_xray_restart() { "$BIN" ctl xray.restart      || true; }
item_cores_restart() {
    msg "Restarting all cores (this restarts every configured protocol, so it takes a moment)"
    "$BIN" ctl cores.restart-all || true
    "$BIN" ctl cores.status      || true
}

# 15) Xray Logs. The access log is a real file, so no socket is needed, but it is
# the file named by the Xray config's `log.access`, which is what the panel's own
# Xray Logs page reads (ServerService.GetXrayLogs -> xray.GetAccessLogPath). The
# binary reports the resolved path so the menu and the dashboard always show the
# same file; an empty value means Xray's access log is off (the shipped default is
# literally "none"), in which case the dashboard's log page is empty too.
item_xray_logs() {
    local log archive
    log="$(info_get xrayAccessLog)"
    archive="$(info_get xrayAccessLogArchive)"
    if [[ -z "$log" ]]; then
        warn "Xray's access log is disabled (log.access is \"none\" in the Xray config)."
        act  "enable it in the panel: Xray Settings -> Log -> access log path, then restart Xray."
        if [[ -n "$archive" && -s "$archive" ]]; then
            act "showing the archived access log instead: ${TEAL}${archive}${R}"
            log="$archive"
        else
            return 0
        fi
    elif [[ ! -f "$log" ]]; then
        warn "the configured access log ${TEAL}${log}${R} does not exist yet. Has Xray logged any traffic?"
        return 0
    fi
    msg "Tailing ${log}   (Ctrl-C returns to the menu)"
    hr
    # Ctrl-C must return to the menu, not kill it: with an INT trap installed bash
    # runs the (no-op) handler instead of dying alongside the tail it is waiting on.
    trap ':' INT
    tail -n 200 -f "$log" || true
    trap - INT
}

# 17) Get SSL.
item_ssl() {
    obtain_letsencrypt_cert || warn "the panel's TLS settings were left exactly as they were."
}

# --------------------------------------------------------------------------- #
#  Menu
# --------------------------------------------------------------------------- #

show_menu() {
    local unit state panel
    unit="$(info_get systemdUnit)";   [[ -n "$unit"  ]] || unit="?"
    state="$(info_get systemdState)"; [[ -n "$state" ]] || state="?"
    panel="stopped"
    [[ "$(info_get panelRunning)" == "true" ]] && panel="running"

    printf '\n'
    hr
    printf '%s[%sVPN-UI%s]%s management   %sv%s%s\n' \
        "$B$TEAL" "$GREEN" "$TEAL" "$R" "$D" "$(info_get version)" "$R"
    printf '  %spanel%s %s   %sunit%s %s (%s)\n' "$D" "$R" "$panel" "$D" "$R" "$unit" "$state"
    hr
    printf '    %s1)%s  Update                 %s10)%s Stop      (systemd)\n'   "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s2)%s  Un-Install             %s11)%s Restart   (systemd)\n'   "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s3)%s  Change Username        %s12)%s Start Xray\n'            "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s4)%s  Change Password        %s13)%s Stop Xray\n'             "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s5)%s  Change Port            %s14)%s Restart Xray\n'          "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s6)%s  Change Web-Path        %s15)%s Xray Logs\n'             "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s7)%s  Reset Login (random)   %s16)%s Restart All Cores\n'     "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s8)%s  View login info        %s17)%s Get SSL (Lets Encrypt)\n' "$GREEN" "$R" "$GREEN" "$R"
    printf '    %s9)%s  Start     (systemd)    %s0)%s  Exit\n'                  "$GREEN" "$R" "$GREEN" "$R"
    hr
}

pause() {
    printf '\n'
    read -r -p "  press Enter to return to the menu... " _ || true
}

menu_loop() {
    local choice
    while true; do
        show_menu
        printf '  choose [0-17]: '
        # EOF (a piped stdin) must leave, not spin forever on an empty read.
        read -r choice || { printf '\n'; return 0; }
        printf '\n'
        case "$choice" in
            1)  item_update ;;
            2)  item_uninstall ;;
            3)  item_username ;;
            4)  item_password ;;
            5)  item_port ;;
            6)  item_webpath ;;
            7)  item_random ;;
            8)  item_info ;;
            9)  item_start ;;
            10) item_stop ;;
            11) item_restart ;;
            12) item_xray_start ;;
            13) item_xray_stop ;;
            14) item_xray_restart ;;
            15) item_xray_logs ;;
            16) item_cores_restart ;;
            17) item_ssl ;;
            0)  return 0 ;;
            "") continue ;;
            *)  warn "invalid choice: '${choice}'" ;;
        esac
        pause
    done
}

usage() {
    cat <<EOF
usage: ${0##*/}            open the management menu
       ${0##*/} ssl        issue/install a Let's Encrypt certificate (non-interactive
                           with DEPLOY_DOMAIN=... DEPLOY_EMAIL=...)
       ${0##*/} --help     this message

environment:
  VPNUI_BIN   path to the panel binary (default: /opt/vpn-ui/vpn-ui-amd64)
EOF
}

# Acquire root: re-exec through sudo when not already root, so `vpn-ui` just works
# for an operator with sudo. Everything this menu does (settings in the root-owned
# DB, systemctl, the root-only control socket) needs it. Mirrors deploy.sh.
require_root() {
    [[ $EUID -eq 0 ]] && return 0
    if [[ -f "$0" ]] && command -v sudo >/dev/null 2>&1; then
        exec sudo -- bash "$0" "$@"
    fi
    die "must run as root. Use: sudo ${0##*/}"
}

require_bin() {
    [[ -x "$BIN" ]] || die "panel binary not found at ${BIN}. Set VPNUI_BIN=/path/to/vpn-ui-amd64 if it lives elsewhere."
}

main() {
    case "${1:-}" in
        -h|--help|help) usage; return 0 ;;
        ssl)
            require_root "$@"
            require_bin
            obtain_letsencrypt_cert
            return $?
            ;;
        "") ;;
        *) die "unknown argument '${1}'. Run '${0##*/}' for the menu, or '${0##*/} --help'." ;;
    esac
    require_root "$@"
    require_bin
    menu_loop
}

# Executed vs sourced. deploy.sh sources this file for obtain_letsencrypt_cert
# alone and must not be re-exec'd through sudo nor land in an interactive menu.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
