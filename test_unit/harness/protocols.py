"""Per-protocol test drivers. Each connects account A (primary + variants),
runs the shared check suite while A stays up, then reconnects account B for
client-to-client (same inbound) and cross-inbound (peer protocol) ping tests.
"""
from __future__ import annotations

import threading
import time

from . import abort
from . import checks
from . import server_setup
from . import traffic
from .clients import openvpn as ovpn
from .clients import l2tp as l2tp_mod
from .clients import pptp as pptp_mod
from .clients import openconnect as oc_mod
from .clients import sstp as sstp_mod
from .clients import ikev2 as ikev2_mod
from .clients import wgc as wgc_mod
from .clients.base import Client
from .model import Phase, SubTest, Status
from .model import (PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP, PHASE_OPENCONNECT,
                    PHASE_SSTP, PHASE_WGC, IKEV2_PHASE_BY_MODE)

# cross-inbound peer: X's cross test pings a client on peer[X]'s inbound
PEER = {"openvpn": "l2tp", "l2tp": "pptp", "pptp": "openvpn",
        "openconnect": "openvpn", "sstp": "openvpn", "ikev2": "openvpn",
        "wg-c": "openvpn"}
# Non-ikev2 protocols map straight to their phase. ikev2 is split per auth mode
# (IKEV2_PHASE_BY_MODE), resolved inside run() from its `mode` arg.
PHASE = {"openvpn": PHASE_OPENVPN, "l2tp": PHASE_L2TP, "pptp": PHASE_PPTP,
         "openconnect": PHASE_OPENCONNECT, "sstp": PHASE_SSTP, "wg-c": PHASE_WGC}

# Connect variant used when dialing the SECOND same-protocol inbound (TEST 1,
# _multi_inbound_check): l2tp uses RAW (the client's IPsec config is pinned to the
# primary's 17/1701, so a 2nd l2tp inbound is exercised over raw L2TP), openvpn
# udp/new, pptp has no variant. sstp/ikev2 have no variant (single-variant protocols).
_SECOND_VARIANT = {"openvpn": ("udp", "new"), "l2tp": "raw", "pptp": None,
                   "openconnect": "dtls", "sstp": None, "ikev2": None,
                   "wg-c": None}


def _connect(client: Client, sc, proto: str, which: str, variant=None, ib=None):
    # `ib` overrides the setup inbound (used to dial a SECOND same-protocol inbound
    # built at runtime); default keeps every existing caller on sc.inbounds[proto].
    if ib is None:
        ib = sc.inbounds[proto]
    if proto == "openvpn":
        transport, cipher = variant or ("udp", "new")
        return ovpn.connect(client, ib, which, transport, cipher, sc.server_ip)
    if proto == "l2tp":
        return l2tp_mod.connect(client, ib, which, ipsec=(variant != "raw"),
                                server_ip=sc.server_ip)
    if proto == "pptp":
        return pptp_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "openconnect":
        return oc_mod.connect(client, ib, which, variant=variant or "dtls",
                              server_ip=sc.server_ip)
    if proto == "sstp":
        return sstp_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "ikev2":
        return ikev2_mod.connect(client, ib, which, server_ip=sc.server_ip)
    if proto == "wg-c":
        return wgc_mod.connect(client, ib, which, server_ip=sc.server_ip)
    raise ValueError(proto)


def _disconnect(client: Client, proto: str):
    {"openvpn": ovpn.disconnect,
     "l2tp": l2tp_mod.disconnect,
     "pptp": pptp_mod.disconnect,
     "openconnect": oc_mod.disconnect,
     "sstp": sstp_mod.disconnect,
     "ikev2": ikev2_mod.disconnect,
     "wg-c": wgc_mod.disconnect}[proto](client)


def _variants(proto: str):
    """(label, variant, is_primary) connect variants for a protocol."""
    if proto == "openvpn":
        return [
            ("connect-udp-new", ("udp", "new"), True),
            ("connect-udp-old", ("udp", "old"), False),
            ("connect-tcp-new", ("tcp", "new"), False),
            ("connect-tcp-old", ("tcp", "old"), False),
        ]
    if proto == "l2tp":
        return [
            ("connect-ipsec", "ipsec", True),
            ("connect-raw", "raw", False),
        ]
    if proto == "openconnect":
        return [
            ("connect-dtls", "dtls", True),
            ("connect-tls", "tls", False),
        ]
    return [("connect", None, True)]


def run(proto: str, cA: Client, cB: Client, cC: Client, sc, cfg: dict, result, panel=None, server_exec=None, mode=None) -> None:
    # Resolve the target phase, inbound, and account model. ikev2 runs once per auth
    # mode: eap-mschapv2 = the primary 2-account inbound (RADIUS path); psk/eap-tls =
    # their single-account inbound (rbridge-sweep path). Non-ikev2 protocols are unchanged
    # (mode is None -> phase/inbound from PHASE[proto] / sc.inbounds[proto]).
    if proto == "ikev2":
        mode = mode or "eap-mschapv2"
        phase: Phase = result.phase(IKEV2_PHASE_BY_MODE[mode])
        if mode == "eap-mschapv2":
            ib = sc.inbounds.get("ikev2")
            single_account = False
        else:
            ib = (getattr(sc, "ikev2_extra", None) or {}).get(mode)
            single_account = True   # the panel binds a psk/eap-tls inbound to ONE account
        present = ib is not None
    else:
        phase = result.phase(PHASE[proto])
        ib = sc.inbounds.get(proto)
        single_account = False
        present = proto in sc.inbounds
    log = cA.log

    def server_log():
        """Server-side daemon log for this protocol (for connect diagnostics)."""
        if panel is None:
            return ""
        try:
            return "\n\n== server " + proto + " log ==\n" + panel.core_logs(proto)
        except Exception:  # noqa: BLE001
            return ""

    if not present:
        phase.add(SubTest(f"{proto}-inbound", Status.SKIP,
                          "inbound was not created in setup"))
        log(f"-> inbound not created in setup -> skipping suite")
        return

    dns_domain = (cfg.get("dns_resolve") or {}).get("domain", "cloudflare.com")

    # ---- connect variants on A (each tested in isolation) --------------
    # Disconnect before AND after every variant so leftover state (e.g. an
    # IPsec SA from the l2tp-ipsec test) can't contaminate the next variant.
    primary_ok = False
    for label, variant, is_primary in _variants(proto):
        if abort.is_set():
            log("-> aborted by user [skip]")
            return
        _disconnect(cA, proto)
        log(f"-> A {label}...")
        st = phase.add(SubTest(label))
        ok, ip, clog = _connect(cA, sc, proto, "A", variant, ib=ib)
        st.log = clog if ok else clog + server_log()
        st.status = Status.PASS if ok else Status.FAIL
        st.detail = f"tunnel ip {ip}" if ok else "connect failed"
        log(f"-> A {label} [{st.status.value}] {st.detail}")
        # per-variant DNS resolution through the tunnel (dig +short). Name it by
        # the variant suffix: connect-udp-new -> dns-resolve-udp-new.
        if ok:
            dns_name = "dns-resolve" + label[len("connect"):]
            dchk = checks.dns_resolve(cA, dns_domain, name=dns_name)
            phase.add(dchk)
            log(f"-> A {dchk.name} [{dchk.status.value}] {dchk.detail}")
        if is_primary:
            primary_ok = ok
        _disconnect(cA, proto)

    # ---- TEST 2: IPsec must NOT be stuck "Stopped" (l2tp/ipsec only) ----
    # L2TP/IPsec (libreswan) can get stuck stopped when GenerateIPsecConfig emits
    # version-wrong keywords; assert it is up when it's expected up (l2tp/ipsec
    # configured + libreswan present). NA when not applicable (no PSK / no
    # libreswan, e.g. Arch). Independent of client state; wrapped so it can't abort.
    if proto == "l2tp":
        try:
            ist = _ipsec_not_stuck(sc.inbounds["l2tp"], panel, server_exec, log)
        except Exception as e:  # noqa: BLE001
            ist = SubTest("ipsec-not-stuck", Status.ERROR, str(e)[:150])
        phase.add(ist)
        log(f"-> {ist.name} [{ist.status.value}] {ist.detail}")

    # Whether the shared check suite can run. The User Limit Strategy test below is
    # INDEPENDENT of it — it reconfigures the inbound (daemon restart = clean slate)
    # — so it always runs, even when the shared suite is skipped (e.g. an intermittent
    # openvpn re-establish failure when the K=2 block is briefly ghost-exhausted).
    suite_ok = primary_ok
    a_primary_ip = ""
    if not primary_ok:
        phase.add(SubTest("suite", Status.SKIP,
                          "primary connection failed; shared checks skipped"))
        log(f"-> primary connect failed -> skipping shared checks (strategy test still runs)")
    else:
        # Bring the primary up fresh for the shared check suite, RETRYING with a full
        # teardown + settle between attempts. Cycling the connect variants just above
        # leaves the daemon mid-teardown of the last variant's session, so an immediate
        # single reconnect can race it freeing the tunnel IP (esp. ocserv releasing the
        # just-used block IP) and intermittently fail — which would wrongly SKIP the
        # entire shared suite (tunnel-egress/internet/dns-leak/user-limit/c2c/routing/
        # cross-inbound) for the phase. The strategy/traffic tests already use this
        # retry (traffic._connect_retry); the shared-suite re-establish was the one
        # connect that didn't, which is why it flaked here and nowhere else.
        ok, a_primary_ip, clog = False, "", ""
        for _ in range(3):
            _disconnect(cA, proto)
            cA.disconnect_all()
            time.sleep(4)
            ok, a_primary_ip, clog = _connect(cA, sc, proto, "A", ib=ib)
            if ok:
                break
        if not ok:
            suite_ok = False
            phase.add(SubTest("suite", Status.SKIP, "could not re-establish primary after retries"))
            log(f"-> could not re-establish primary -> skipping shared checks (strategy test still runs)")

    if suite_ok:
        # ---- shared check suite (A stays connected) --------------------
        # NOTE: the source-IP `routing` check runs later, in the client-to-client
        # block, where BOTH clients are connected (A = freedom, B = blackhole).
        log(f"-> running checks (tunnel-egress, internet, dns-leak)...")
        # Run each check independently: a raising check must not abort the others.
        check_fns = [
            ("tunnel-egress", lambda: checks.tunnel_egress(cA)),
            ("internet", lambda: checks.internet(cA)),
            ("dns-leak", lambda: checks.dns_leak(cA, cfg)),
        ]
        for name, fn in check_fns:
            try:
                chk = fn()
            except Exception as e:  # noqa: BLE001
                chk = SubTest(name, Status.ERROR, str(e)[:150])
            log(f"-> {chk.name} [{chk.status.value}] {chk.detail}")
            phase.add(chk)

        # ---- User Limit: a 2nd device on the SAME account --------------
        # With user_limit K>1 the account owns a block; the 2nd device must get a
        # DISTINCT IP inside that block (A device 1 = cA, still up) and reach the
        # internet. cB is idle here (client-to-client connects it later).
        if proto == "wg-c":
            phase.add(SubTest("user-limit", Status.NA,
                              "WireGuard gateway model: one keypair per account; the block "
                              "(e.g. /29) IS the limit, not per-device enforcement"))
            log("-> user-limit [na] gateway model (one keypair per account)")
        elif ib is not None and getattr(ib, "user_limit", 1) > 1:
            _user_limit_check(proto, cA, cB, sc, a_primary_ip, ib, log, phase)

        # ---- client-to-client + routing + cross-inbound (need account B) --
        # These need a SECOND account (B). Single-account modes (ikev2 psk/eap-tls,
        # which the panel binds to exactly one account) have only account A, so they
        # are Not Applicable there (source-IP A/B split is covered by eap-mschapv2).
        if single_account:
            for nm, why in (("client-to-client", "single-account mode: no 2nd account"),
                            ("routing", "single-account mode: no A/B split"),
                            ("cross-inbound", "single-account mode: no 2nd account")):
                phase.add(SubTest(nm, Status.NA, why))
                log(f"-> {nm} [na] {why}")
        else:
            # ---- client-to-client (same inbound) ----------------------
            log(f"-> client-to-client (B on same inbound)...")
            c2c = SubTest("client-to-client")
            cB.disconnect_all()          # clean slate on B before its connect
            time.sleep(2)
            okB, ipB, logB = _connect(cB, sc, proto, "B")
            rt = SubTest("routing")
            if okB:
                res = checks.ping_peer("client-to-client", cA, ipB, must_reach=True)
                c2c.status, c2c.detail, c2c.log = res.status, res.detail, res.log
                # source-IP routing proof: A (freedom) is still up, B (blackhole) is up
                # now — assert the split from connectivity while both are connected.
                try:
                    r = checks.routing(cA, cB)
                    rt.status, rt.detail, rt.log = r.status, r.detail, r.log
                except Exception as e:  # noqa: BLE001
                    rt.status, rt.detail = Status.ERROR, str(e)[:150]
            else:
                c2c.status = Status.SKIP
                c2c.detail = "peer B (same protocol) failed to connect"
                c2c.log = logB
                rt.status = Status.SKIP
                rt.detail = "peer B (blackhole client) failed to connect"
            log(f"-> client-to-client [{c2c.status.value}] {c2c.detail}")
            phase.add(c2c)
            log(f"-> routing [{rt.status.value}] {rt.detail}")
            phase.add(rt)
            _disconnect(cB, proto)

            # ---- cross-inbound (peer protocol) ------------------------
            peer = PEER[proto]
            log(f"-> cross-inbound (B on peer '{peer}')...")
            cross = SubTest("cross-inbound")
            if peer not in sc.inbounds:
                cross.status = Status.SKIP
                cross.detail = f"peer inbound '{peer}' not available"
            else:
                # Full teardown on B (esp. strongswan/charon after an l2tp-ipsec run,
                # which otherwise deactivates the fresh ppp0 of the peer protocol),
                # then settle before connecting the peer.
                cB.disconnect_all()
                time.sleep(3)
                okP, ipP, logP = _connect(cB, sc, peer, "B")
                if okP:
                    res = checks.ping_peer("cross-inbound", cA, ipP, must_reach=True)
                    cross.status, cross.detail, cross.log = res.status, res.detail, res.log
                else:
                    cross.status = Status.SKIP
                    cross.detail = f"peer {peer} on B failed to connect"
                    cross.log = logP
                _disconnect(cB, peer)
            log(f"-> cross-inbound [{cross.status.value}] {cross.detail}")
            phase.add(cross)

    # ---- User Limit Strategy: reject vs accept on a 3rd device ---------
    # Always runs (independent of the shared suite): it restarts the daemon.
    # WireGuard is the exception: an account owns exactly K device keypairs (a peer's
    # key IS its credential), so there is no dynamic (K+1)th-device admission to reject
    # or evict — the cap is structural. The device COUNT and its hard disable/quota
    # enforcement are covered by user-limit / multi-user-total / account-termination.
    if proto == "wg-c":
        for nm in ("strategy-reject", "strategy-accept"):
            phase.add(SubTest(nm, Status.NA,
                              "WireGuard: K device keypairs are structural — no dynamic "
                              "(K+1)th admission to reject/evict"))
            log(f"-> {nm} [na] structural K (no dynamic admission)")
    elif ib is not None and getattr(ib, "user_limit", 1) > 1 and panel is not None:
        _strategy_check(proto, cA, cB, cC, sc, ib, panel, log, phase, server_exec)

    # ---- WireGuard preshared-key mode ----------------------------------
    # Prove the optional PSK mode works end-to-end: a separate psk-enabled wgc inbound,
    # a real handshake + internet through it, then tear it down. Covers "with and without
    # preshared key" (the primary suite above ran the no-PSK path).
    if proto == "wg-c" and panel is not None:
        try:
            pk = _wgc_psk_check(cC, sc, panel, log)
        except Exception as e:  # noqa: BLE001
            pk = SubTest("psk-mode", Status.ERROR, str(e)[:150])
        phase.add(pk)
        log(f"-> {pk.name} [{pk.status.value}] {pk.detail}")
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    # ---- OpenConnect same-NAT device limit -----------------------------
    # Two devices on ONE account from ONE source IP (two phones on home wifi). ocserv
    # sends no NAS-Port, so both share a Calling-Station-Id — the E2E's separate client
    # VMs have distinct IPs and can't hit this, so cA opens a SECOND tunnel (tun1)
    # itself. Each device must get a DISTINCT routable block IP; the idempotent-redial
    # cache used to collapse them onto one IP → 2nd device no internet (the real report).
    if proto == "openconnect" and ib is not None and getattr(ib, "user_limit", 1) > 1:
        _oc_same_nat_check(cA, sc, ib, log, phase, server_exec)

    # ---- User Limit: traffic AGGREGATION across the account's devices --
    # Prove the account's counted traffic is the SUM over its K simultaneous
    # devices, not per-device / not just one. Runs AFTER the strategy check (which
    # leaves a clean all-down slate) and BEFORE the usage/termination block (which
    # resets the counter fresh and, in termination, DISABLES account A — so this
    # must precede it). Independent of the shared suite; wrapped so a raising test
    # can't abort the phase.
    if proto == "wg-c":
        phase.add(SubTest("multi-user-total", Status.NA,
                          "WireGuard gateway model: one keypair per account, no per-device "
                          "traffic split to aggregate"))
        log("-> multi-user-total [na] gateway model (one keypair per account)")
    elif ib is not None and getattr(ib, "user_limit", 1) > 1 and panel is not None:
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        mu_clients = [cA, cB, cC]
        # per-client closure -> all connect onto the SAME account "A" (device 1..N)
        mu_connect = [(lambda c=c: _connect(c, sc, proto, "A", ib=ib)) for c in mu_clients]
        try:
            mu = traffic.multi_user_total(mu_clients, panel, ib, cfg, mu_connect, log,
                                          server_exec=server_exec)
        except Exception as e:  # noqa: BLE001
            mu = SubTest("multi-user-total", Status.ERROR, str(e)[:150])
        log(f"-> {mu.name} [{mu.status.value}] {mu.detail}")
        phase.add(mu)
        for c in (cA, cB, cC):
            _disconnect(c, proto)
            c.disconnect_all()
        time.sleep(2)

    # ---- TEST 1: multiple inbounds of the SAME protocol ----------------
    # Prove the panel supports 2+ inbounds of one protocol at once. Independent of
    # the shared suite (it builds & tears down its OWN 2nd inbound). Runs BEFORE the
    # traffic block, which disables account A on the primary. Wrapped so a raising
    # test can't abort the phase.
    if single_account:
        phase.add(SubTest("multi-inbound-same-proto", Status.NA,
                          "single-account mode: covered by the eap-mschapv2 phase"))
        log("-> multi-inbound-same-proto [na] single-account mode")
    elif panel is not None:
        try:
            mi = _multi_inbound_check(proto, cA, cB, cC, sc, panel, log)
        except Exception as e:  # noqa: BLE001
            mi = SubTest("multi-inbound-same-proto", Status.ERROR, str(e)[:150])
        phase.add(mi)
        log(f"-> {mi.name} [{mi.status.value}] {mi.detail}")
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    # ---- traffic accounting: usage counting + termination on limit -----
    # Runs LAST on account A (freedom-routed) — it burns/limits A, which is
    # disposable now that every other check is done. Each drives real traffic
    # through the tunnel and reads the panel's counter back.
    if ib is not None and panel is not None:
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        connect_A = lambda: _connect(cA, sc, proto, "A", ib=ib)  # noqa: E731
        u = traffic.usage(cA, panel, ib, cfg, connect_A, log, server_exec=server_exec)
        log(f"-> {u.name} [{u.status.value}] {u.detail}")
        phase.add(u)
        _disconnect(cA, proto)
        cA.disconnect_all()
        time.sleep(2)
        t = traffic.termination(cA, panel, ib, cfg, connect_A, log)
        log(f"-> {t.name} [{t.status.value}] {t.detail}")
        phase.add(t)

    # (ikev2 psk/eap-tls now run their OWN full suite via run(mode=...), one phase per
    # mode — the old connect-only smoke block here is gone.)
    _disconnect(cA, proto)


def _user_limit_check(proto, cA, cB, sc, a_primary_ip, ib, log, phase) -> None:
    """Prove per-account User Limit blocks: a 2nd device on account A (on cB,
    while A's 1st device on cA stays up) gets a DISTINCT IP inside A's aligned
    block and reaches the internet. This exercises the runtime allocator (RADIUS
    free-list for l2tp/pptp, connect-hook lease for openvpn)."""
    ul = SubTest("user-limit")
    log(f"-> user-limit (2nd device on account A, K={ib.user_limit})...")
    cB.disconnect_all()
    time.sleep(2)
    ok2, ip2, log2 = _connect(cB, sc, proto, "A", ib=ib)  # SAME account A -> device 2
    try:
        if not ok2 or not ip2:
            ul.status, ul.detail, ul.log = Status.FAIL, "2nd device failed to connect", log2
        elif ip2 == a_primary_ip:
            ul.status = Status.FAIL
            ul.detail = f"both devices got the SAME ip {ip2} (block allocation broken)"
        else:
            # Account A's K device IPs are a CONSECUTIVE [base, base+K) range in one
            # /24. device1 (a_primary_ip) connected first so it holds the block BASE
            # — derive the expected range from the ACTUAL device1 IP rather than
            # recomputing it (the inbound id is NOT the range's third octet in
            # general: nextFreeSubnet may pick a different /24).
            prefix3, base_str = a_primary_ip.rsplit(".", 1)
            base = int(base_str)
            block = {f"{prefix3}.{base + d}" for d in range(ib.user_limit)}
            rng = f"{prefix3}.{base}..{prefix3}.{base + ib.user_limit - 1}"
            d2_in = ip2 in block
            c1 = checks.internet(cA)
            c2 = checks.internet(cB)
            both = c1.status == Status.PASS and c2.status == Status.PASS
            ul.log = (f"device1 {a_primary_ip} (block base)\ndevice2 {ip2} in [{rng}]={d2_in}\n"
                      f"net1={c1.status.value} net2={c2.status.value}\n{c2.log}")
            if d2_in and both:
                ul.status = Status.PASS
                ul.detail = f"2 devices on 1 account (K={ib.user_limit}): {a_primary_ip} + {ip2} in [{rng}], both online"
            else:
                ul.status = Status.FAIL
                ul.detail = (f"d1={a_primary_ip} d2={ip2}(in={d2_in}) "
                             f"net1={c1.status.value} net2={c2.status.value}")
    except Exception as e:  # noqa: BLE001
        ul.status, ul.detail = Status.ERROR, str(e)[:150]
    log(f"-> user-limit [{ul.status.value}] {ul.detail}")
    phase.add(ul)
    _disconnect(cB, proto)
    cB.disconnect_all()
    time.sleep(2)


def _strategy_check(proto, cA, cB, cC, sc, ib, panel, log, phase, server_exec=None) -> None:
    """Prove the User Limit Strategy on a K=2 account. With 2 devices already up
    (cA=device1/oldest, cB=device2), a 3rd device (cC) is:
      - REJECTED under strategy="reject" (cC never gets a working tunnel), and
      - ADMITTED under strategy="accept", which disconnects the OLDEST device (cA).
    The inbound is reconfigured in place between the two sub-tests; the panel's
    on<Proto>Changed hook regenerates config + restarts the daemon (clean slate).

    Eviction detection differs by protocol:
      - l2tp/pptp: cA's tunnel interface DROPS (the ppp link is torn down and the
        CLI client does not auto-redial) — watched in a background thread.
      - openvpn: the client keeps tun0 up (persist-tun) and auto-reconnects, so the
        client side can't see the drop. Instead assert SERVER-SIDE that the account
        never exceeds K live sessions: the status file's CLIENT_LIST count stays <=K
        when the oldest was evicted, vs 3 (a duplicate) when it was not."""
    iface = "tun0" if proto in ("openvpn", "openconnect") else "ppp0"

    def all_down():
        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)

    def watch_drop(c, window=30):
        """Poll c's tunnel iface in a background thread for the whole duration of
        the 3rd device's connect. Returns (thread, flag); flag['v'] becomes True
        the instant the iface loses its IP — the server-side eviction — even if an
        OpenVPN client then auto-reconnects and brings the iface back seconds later
        (which a single post-connect check would miss)."""
        flag = {"v": False}

        def _poll():
            end = time.monotonic() + window
            while time.monotonic() < end and not flag["v"]:
                if not c.wait_iface(iface, timeout=1):
                    flag["v"] = True
                    return
                time.sleep(1)

        th = threading.Thread(target=_poll, daemon=True)
        th.start()
        return th, flag

    # ---------- strategy = reject ----------
    log(f"-> user-limit-strategy REJECT (K={ib.user_limit})...")
    rj = phase.add(SubTest("strategy-reject"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "reject")
        time.sleep(6)  # daemon restart + config apply
        ok1, ip1, _ = _connect(cA, sc, proto, "A", ib=ib)
        time.sleep(2)
        ok2, ip2, _ = _connect(cB, sc, proto, "A", ib=ib)
        time.sleep(2)
        ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # 3rd device must be refused
        n3 = checks.internet(cC) if ok3 else None
        admitted = ok3 and n3 is not None and n3.status == Status.PASS

        # Causation: with K == the account's block size, a 3rd device is unroutable even
        # with NO cap, so "3rd didn't reach the internet" proves nothing on its own.
        # Assert the SERVER actively refused it. l2tp/pptp: the in-panel RADIUS logs an
        # explicit user-limit rejection. openvpn: the account must NOT gain a 3rd live
        # session (an over-admit would show K+1 CLIENT_LIST rows inside its block).
        refused = False
        sig = ""
        if proto == "openvpn":
            rows = _ovpn_status_rows(server_exec, ib.inbound_id, "udp")
            live = 0
            if ip1:
                p3, b = ip1.rsplit(".", 1)
                block = {f"{p3}.{int(b) + d}" for d in range(ib.user_limit)}
                live = sum(1 for r in rows if len(r) > 3 and r[3] in block)
            refused = 0 < live <= ib.user_limit
            sig = f"live_sessions={live} (cap K={ib.user_limit})"
        else:
            if server_exec is not None:
                try:
                    _, rlog, _ = server_exec(
                        "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                        "grep 'user-limit reached' | tail -1")
                    refused = "user-limit reached" in (rlog or "")
                except Exception:  # noqa: BLE001
                    pass
            sig = f"radius_reject_logged={refused}"

        rj.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3} net={(n3.status.value if n3 else 'n/a')} | {sig}\n{clog3[-400:]}")
        if ok1 and ok2 and not admitted and refused:
            rj.status = Status.PASS
            rj.detail = f"2 devices up; 3rd actively refused [{sig}]"
        else:
            rj.status = Status.FAIL
            rj.detail = f"expected 3rd actively refused; dev1={ok1} dev2={ok2} admitted={admitted} {sig}"
    except Exception as e:  # noqa: BLE001
        rj.status, rj.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-reject [{rj.status.value}] {rj.detail}")

    # ---------- strategy = accept ----------
    log(f"-> user-limit-strategy ACCEPT (K={ib.user_limit})...")
    ac = phase.add(SubTest("strategy-accept"))
    try:
        all_down()
        panel.set_user_limit_strategy(ib.inbound_id, "accept")
        time.sleep(6)
        ok1, ip1, _ = _connect(cA, sc, proto, "A", ib=ib)   # device1 = oldest
        time.sleep(5)                                # firmly establish (must be evictable)
        ok2, ip2, _ = _connect(cB, sc, proto, "A", ib=ib)   # device2
        time.sleep(4)
        if proto == "openvpn":
            # Server-side, churn-proof: capture cA's ORIGINAL session client-id, then
            # assert it's gone after cC joins. persist-tun + auto-reconnect mean cA's
            # tunnel stays up client-side and cA may reconnect with a NEW id, but its
            # original session being killed is the eviction. (A raw session count is
            # unstable during the reconnect war.)
            rows_before = _ovpn_status_rows(server_exec, ib.inbound_id, "udp")
            victim_cid = _ovpn_cid_at_ip(rows_before, ip1)
            ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # device3: admitted, evicts oldest
            # The detached evictor kills the victim ~1.5s after the connect hook returns,
            # but OpenVPN only rewrites the status file on a FIXED 5s timer (unanchored to
            # the kill), so the victim's ORIGINAL client-id can linger in the file for up to
            # one refresh past the kill. A single read at +6s races that timer. Poll for the
            # cid's disappearance instead (up to ~18s = 3+ refreshes). A monotonic client-id
            # never returns once killed (a reconnect gets a NEW id), and eviction that never
            # fired keeps the cid present through every poll — so this can't mask over-admit.
            still = True
            for _ in range(9):
                time.sleep(2)
                still = _ovpn_cid_present(
                    _ovpn_status_rows(server_exec, ib.inbound_id, "udp"), victim_cid)
                if victim_cid != "" and not still:
                    break
            evicted = ok3 and victim_cid != "" and not still
            evwhy = f"cA orig client-id={victim_cid or '?'} present_after={still} (absent ⇒ evicted)"
        else:
            # Client-side: watch cA's tunnel drop, starting BEFORE cC connects (the
            # eviction fires during cC's connect). The l2tp CLI client has no LCP-echo
            # keepalive, so it can be slow to tear ppp0 down after the server kills its
            # end — making the client-side drop RACE-prone. So ALSO corroborate the
            # eviction SERVER-SIDE: the RADIUS service logs "evicted oldest device
            # proto=<p>" exactly when accept-strategy kicks a device. That log line is
            # a churn-proof fact regardless of when the client notices the drop. Pass
            # if EITHER signal fires (the product really evicted).
            watcher, dropped = watch_drop(cA)
            ok3, ip3, clog3 = _connect(cC, sc, proto, "A", ib=ib)  # device3: admitted, evicts oldest
            watcher.join(timeout=18)
            server_evicted = False
            if server_exec is not None:
                try:
                    _, ev, _ = server_exec(
                        "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                        "grep 'evicted oldest device' | grep 'proto=%s' | tail -1" % proto)
                    server_evicted = "evicted oldest device" in (ev or "")
                except Exception:  # noqa: BLE001
                    pass
            # Causative corroboration: eviction tears down the victim's ppp link on the
            # SERVER (killPPPByIP deletes the interface whose peer is dev1's IP), so that
            # IP must no longer be present on any server ppp interface. This is a
            # churn-proof data-plane fact — unlike the log line alone (which could fire
            # without the link dropping) or the race-prone client-side poll.
            link_gone = None
            if server_exec is not None and ip1:
                try:
                    _, addrs, _ = server_exec(
                        "ip -o addr show 2>/dev/null | grep 'peer %s/' || true" % ip1)
                    link_gone = (addrs or "").strip() == ""
                except Exception:  # noqa: BLE001
                    pass
            # Pass requires the eviction to have actually happened, proven server-side by
            # the churn-proof RADIUS "evicted oldest device" log (server_evicted): the panel
            # emits it only after deleting the victim's session AND killing its link. That is
            # CORROBORATED by the victim's tunnel really dropping — but accept-strategy REUSES
            # the victim's IP for the incoming device, so the server-side `peer <ip>/` probe
            # (link_gone) reads False the instant dev3 takes that IP over — a false negative,
            # not a lingering victim. So accept EITHER corroboration: the victim's client-side
            # drop (authoritative for openconnect — DPD tears tun0 down within seconds; the
            # race-prone fallback for the keepalive-less l2tp CLI) OR the server link gone.
            if server_exec is not None:
                evicted = server_evicted and (dropped["v"] or link_gone is not False)
            else:
                evicted = dropped["v"]
            evwhy = (f"dev1 dropped(client)={dropped['v']} server-evicted={server_evicted} "
                     f"link_gone={link_gone}")
        ac.log = (f"dev1={ok1}/{ip1} dev2={ok2}/{ip2}\n"
                  f"dev3 conn={ok3}/{ip3}\n{evwhy}\n{clog3[-400:]}")
        if ok1 and ok2 and ok3 and evicted:
            ac.status = Status.PASS
            ac.detail = f"3rd admitted ({ip3}); oldest device (dev1) disconnected [{evwhy}]"
        else:
            ac.status = Status.FAIL
            ac.detail = (f"admitted(conn)={ok3} evicted={evicted} "
                         f"(dev1={ok1} dev2={ok2}; {evwhy})")
    except Exception as e:  # noqa: BLE001
        ac.status, ac.detail = Status.ERROR, str(e)[:150]
    log(f"-> strategy-accept [{ac.status.value}] {ac.detail}")

    all_down()


def _oc_same_nat_check(cA, sc, ib, log, phase, server_exec=None):
    """Two OpenConnect devices on ONE account from ONE source IP (same VM → same
    Calling-Station-Id; ocserv sends no NAS-Port). Each must get a DISTINCT block IP.
    The idempotent-redial cache used to collapse them onto one IP so the 2nd device
    got no routable address / never came up — the reported "new client no internet"."""
    st = phase.add(SubTest("same-nat-limit"))
    log(f"-> same-nat-limit (2 devices on account A, ONE source IP, K={ib.user_limit})...")
    try:
        cA.disconnect_all()
        cA.sh("pkill -f openconnect 2>/dev/null; true")
        time.sleep(3)
        ok1, ip1, _ = oc_mod.connect(cA, ib, "A", variant="dtls",
                                     server_ip=sc.server_ip, iface="tun0",
                                     keep_existing=False)
        time.sleep(3)
        ok2, ip2, log2 = oc_mod.connect(cA, ib, "A", variant="dtls",
                                        server_ip=sc.server_ip, iface="tun1",
                                        keep_existing=True)
        time.sleep(3)
        ip1_now = cA.wait_iface("tun0", timeout=5)
        ip2_now = cA.wait_iface("tun1", timeout=5)
        distinct = bool(ok1 and ok2 and ip1_now and ip2_now and ip1_now != ip2_now)
        # server-side evidence: the two Access-Accept IPs the panel handed out.
        srv = ""
        if server_exec is not None:
            try:
                _, srv, _ = server_exec(
                    "journalctl -u vpn-ui-panel --no-pager 2>/dev/null | "
                    "grep 'auth accepted (PAP)' | grep 'nas=openconnect' | tail -4")
            except Exception:  # noqa: BLE001
                pass
        st.log = (f"dev1 tun0={ip1_now!r} dev2 tun1={ip2_now!r} distinct={distinct}\n"
                  f"server auth log:\n{srv}\n{log2[-400:]}")
        if distinct:
            st.status = Status.PASS
            st.detail = (f"2 same-NAT devices on 1 account each got a DISTINCT IP "
                         f"({ip1_now}, {ip2_now}) — no idempotent-redial collapse")
        else:
            st.status = Status.FAIL
            st.detail = (f"same-NAT COLLAPSE: dev1={ip1_now!r} dev2={ip2_now!r} "
                         f"(ok1={ok1} ok2={ok2}) — 2nd device didn't get a distinct IP")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        cA.sh("pkill -f openconnect 2>/dev/null; true")
        time.sleep(1)
    log(f"-> same-nat-limit [{st.status.value}] {st.detail}")


def _wgc_psk_check(spare, sc, panel, log) -> SubTest:
    """Prove WireGuard preshared-key mode end-to-end: build a psk-enabled wgc inbound
    (single account), require a real handshake + internet through it, then delete it. The
    primary wgc suite ran the no-PSK path, so together they cover both modes."""
    st = SubTest("psk-mode")
    log("-> psk-mode (preshared-key wgc inbound: handshake + internet)...")
    acct = server_setup._acct("wgpsk", 0)
    settings = {
        "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
        "pskEnable": True,
        "clientToClient": True, "crossInbound": True,
        "clients": [server_setup._dict_client(acct)],
    }
    second = None
    try:
        inb = panel.add_inbound("test-wgc-psk", 51822, "wg-c", settings)
        second = server_setup.Inbound(
            protocol="wg-c", inbound_id=inb["id"], udp_port=51822, tcp_port=0,
            accounts={"A": acct}, user_limit=1)
        server_setup._fetch_wg_configs(panel, second)
        time.sleep(4)   # peer add + interface up
        spare.disconnect_all()
        time.sleep(2)
        ok, ip, clog = wgc_mod.connect(spare, second, "A", server_ip=sc.server_ip)
        net = checks.internet(spare) if ok else None
        works = bool(ok and net and net.status == Status.PASS)
        cfg0 = (second.wg_configs.get("A") or [{}])[0]
        has_psk = "PresharedKey" in (cfg0.get("config") or "")
        st.log = (f"psk_in_config={has_psk} connect_ok={ok} ip={ip!r} "
                  f"net={net.status.value if net else 'n/a'}\n{clog[-500:]}")
        if works and has_psk:
            st.status = Status.PASS
            st.detail = f"preshared-key tunnel established ({ip}) with internet"
        elif not has_psk:
            st.status = Status.FAIL
            st.detail = "psk mode enabled but the rendered client config has no PresharedKey line"
        else:
            st.status = Status.FAIL
            st.detail = (f"psk tunnel did not pass traffic "
                         f"(ok={ok} net={net.status.value if net else 'n/a'})")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        wgc_mod.disconnect(spare)
        spare.disconnect_all()
        if second is not None:
            try:
                panel.del_inbound(second.inbound_id)
                time.sleep(3)
            except Exception:  # noqa: BLE001
                pass
    return st


def _ovpn_status_rows(server_exec, inbound_id, transport):
    """Parse the server's OpenVPN status-v3 file into CLIENT_LIST rows (each a list
    of tab fields: [0]CLIENT_LIST [3]VirtualAddr [10]ClientID). [] if unreadable."""
    if server_exec is None:
        return []
    try:
        _, out, _ = server_exec(
            f"cat /var/run/openvpn/status-{inbound_id}-{transport}.log 2>/dev/null")
    except Exception:  # noqa: BLE001
        return []
    return [ln.split("\t") for ln in out.split("\n") if ln.startswith("CLIENT_LIST\t")]


def _ovpn_cid_at_ip(rows, ip) -> str:
    """Client-ID of the session holding virtual address `ip` ("" if none)."""
    for f in rows:
        if len(f) > 10 and f[3] == ip:
            return f[10].strip()
    return ""


def _ovpn_cid_present(rows, cid) -> bool:
    """True if any session has client-ID `cid` (False for cid="")."""
    return bool(cid) and any(len(f) > 10 and f[10].strip() == cid for f in rows)


def _iface_up(client: Client, proto: str) -> bool:
    iface = "tun0" if proto in ("openvpn", "openconnect") else "ppp0"
    return bool(client.wait_iface(iface, timeout=3))


def _multi_inbound_check(proto, cA, cB, cC, sc, panel, log) -> SubTest:
    """TEST 1: prove the panel supports MULTIPLE inbounds of the SAME protocol at
    once. Create a SECOND inbound of `proto` (distinct port + IP pool + its own
    account), connect a spare client to it and reach the internet, then prove the
    FIRST (setup) inbound STILL works — distinct tunnel IP, no port/pool clash. The
    2nd inbound is DELETED at the end so it can't pollute later phases.

    For l2tp/pptp the daemon binds one fixed port (1701/1723) for every inbound, so
    the 2nd inbound is reached by connecting with ITS account (RADIUS lands it in
    the 2nd inbound's distinct /24 pool); only openvpn listens on its own per-inbound
    port. Either way the proof is: both inbounds online, on distinct pools."""
    st = SubTest("multi-inbound-same-proto")
    log(f"-> multi-inbound-same-proto (2nd {proto} inbound, new port/pool)...")
    spare = cC          # cA/cB drive the shared suite; cC is free at this point
    variant = _SECOND_VARIANT.get(proto)
    second = None
    try:
        try:
            second = server_setup.build_second_inbound(panel, proto)
        except Exception as e:  # noqa: BLE001
            # The panel refusing a 2nd same-proto inbound is the very regression
            # this test guards -> FAIL (not SKIP), carrying the panel error.
            st.status = Status.FAIL
            st.detail = f"could not create a 2nd {proto} inbound: {str(e)[:120]}"
            st.log = str(e)[:500]
            return st
        time.sleep(6)   # new-inbound save -> config regen + daemon restart

        for c in (cA, cB, cC):
            c.disconnect_all()
        time.sleep(2)
        # (a) connect the spare client to the 2nd inbound's OWN account
        ok2, ip2, log2 = _connect(spare, sc, proto, "A", variant, ib=second)
        net2 = checks.internet(spare) if (ok2 and ip2) else None
        second_ok = bool(ok2 and ip2 and net2 and net2.status == Status.PASS)
        _disconnect(spare, proto)
        spare.disconnect_all()
        time.sleep(2)
        # (b) prove the FIRST (setup) inbound still works (dial its account A)
        ok1, ip1, log1 = _connect(spare, sc, proto, "A", variant)   # primary
        net1 = checks.internet(spare) if (ok1 and ip1) else None
        first_ok = bool(ok1 and ip1 and net1 and net1.status == Status.PASS)
        _disconnect(spare, proto)
        spare.disconnect_all()
        time.sleep(2)

        # distinct tunnel IP AND distinct /24 pool (different inbounds own different
        # /24s, so the third octet differs) -> proves separate pools, no clash.
        distinct = bool(ip1 and ip2 and ip1 != ip2
                        and ip1.split(".")[2] != ip2.split(".")[2])
        p1, p2 = sc.inbounds[proto].udp_port, second.udp_port
        st.log = (f"2nd inbound id={second.inbound_id} port={p2} variant={variant}: "
                  f"conn={ok2} ip={ip2!r} net={net2.status.value if net2 else 'n/a'}\n"
                  f"1st inbound id={sc.inbounds[proto].inbound_id} port={p1}: "
                  f"conn={ok1} ip={ip1!r} net={net1.status.value if net1 else 'n/a'}\n"
                  f"distinct tunnel IP + distinct /24 pool: {distinct}\n"
                  f"-- 2nd connect --\n{log2[-350:]}\n-- 1st connect --\n{log1[-350:]}")
        if second_ok and first_ok and distinct:
            st.status = Status.PASS
            st.detail = (f"two {proto} inbounds coexist: 2nd(:{p2},{ip2}) + "
                         f"1st(:{p1},{ip1}) both online on distinct pools")
        elif not second_ok:
            st.status = Status.FAIL
            st.detail = (f"2nd {proto} inbound not usable "
                         f"(conn={ok2} ip={ip2!r} net={net2.status.value if net2 else 'n/a'})")
        elif not first_ok:
            st.status = Status.FAIL
            st.detail = (f"1st {proto} inbound broke after adding a 2nd "
                         f"(conn={ok1} ip={ip1!r} net={net1.status.value if net1 else 'n/a'})")
        else:
            st.status = Status.FAIL
            st.detail = f"both online but tunnel IPs/pools not distinct (ip1={ip1} ip2={ip2})"
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    finally:
        # clean up the 2nd inbound so it can't pollute later phases (bulk-ops etc.)
        if second is not None:
            try:
                panel.del_inbound(second.inbound_id)
                time.sleep(4)
            except Exception as e:  # noqa: BLE001
                st.log += f"\n(cleanup: del 2nd inbound failed: {e})"
    return st


def _ipsec_not_stuck(ib, panel, server_exec, log) -> SubTest:
    """TEST 2 (l2tp only): L2TP/IPsec uses libreswan; a known regression is IPsec
    "stuck on Stopped" from version-dependent config keywords (GenerateIPsecConfig
    version-gates against exactly this). Assert IPsec is NOT stuck stopped when it's
    expected up (l2tp/ipsec configured AND libreswan present). NA when not applicable
    (inbound has no PSK, or libreswan unavailable on the host, e.g. Arch). FAIL only
    when it was expected up but the service is inactive.

    Two corroborating signals: the panel's dedicated `ipsec` core status
    (state=running = ipsec.service active; state!=not_installed = `ipsec` CLI
    present) and a server-side probe (`systemctl is-active ipsec`, `ipsec
    status/whack`). OR'd toward PASS so a FAIL means BOTH views agree IPsec is
    down."""
    st = SubTest("ipsec-not-stuck")
    log("-> ipsec-not-stuck (l2tp/ipsec must not be stuck Stopped)...")
    try:
        # IPsec is now its OWN core in /panel/core/status (was buried in the l2tp
        # core's extra={ipsec,libreswan}). state=="running" -> ipsec.service active;
        # state!="not_installed" -> libreswan (`ipsec` CLI) present on the host.
        core = panel.core("ipsec") if panel is not None else {}
        state = core.get("state", "?")
        p_ipsec = state == "running"
        p_libreswan = state not in ("", "?", "not_installed")
        # server-side corroboration (POSIX sh; printf avoids `echo -n` quirks).
        sdump = ""
        if server_exec is not None:
            try:
                _, sdump, _ = server_exec(
                    "printf 'is-active=%s\\n' \"$(systemctl is-active ipsec 2>/dev/null)\"; "
                    "printf 'have=%s\\n' \"$(command -v ipsec >/dev/null 2>&1 && echo yes || echo no)\"; "
                    "echo '--- ipsec status ---'; ipsec status 2>/dev/null | tail -n 15; "
                    "echo '--- whack ---'; ipsec whack --status 2>/dev/null | tail -n 15")
            except Exception as e:  # noqa: BLE001
                sdump = f"(server ipsec query failed: {e})"
        s_active = "is-active=active" in sdump
        s_have = "have=yes" in sdump
        libreswan_avail = p_libreswan or s_have
        ipsec_up = p_ipsec or s_active
        st.log = (f"panel ipsec core: state={state} (running={p_ipsec} "
                  f"libreswan_present={p_libreswan})\n"
                  f"server: is-active(active)={s_active} have-ipsec={s_have}\n{sdump[:1200]}")
        if not getattr(ib, "psk", ""):
            st.status = Status.NA
            st.detail = "l2tp inbound has no IPsec PSK (ipsec not requested) — not applicable"
        elif not libreswan_avail:
            st.status = Status.NA
            st.detail = "libreswan/IPsec unavailable on this host (e.g. Arch) — L2TP/IPsec not applicable"
        elif ipsec_up:
            st.status = Status.PASS
            st.detail = (f"IPsec service active (not stuck stopped): "
                         f"panel.ipsec={p_ipsec} server.active={s_active}")
        else:
            st.status = Status.FAIL
            st.detail = ("IPsec STUCK stopped: libreswan present + l2tp/ipsec configured, "
                         f"but ipsec service inactive (panel.ipsec={p_ipsec} "
                         f"server.active={s_active}, l2tp state={state})")
    except Exception as e:  # noqa: BLE001
        st.status, st.detail = Status.ERROR, str(e)[:150]
    return st
