"""Server-setup phase: build one inbound per protocol (each with 2 accounts),
add two email-based source-IP routing rules against the built-in outbounds
(A-accounts -> `direct`/freedom, B-accounts -> `blocked`/blackhole), and assert
the panel translated the blackhole rule to a per-client source-IP rule.

Topology (chosen so no port/tag collisions and both client VMs are reused):
  - one inbound per protocol, clientToClient + crossInbound both enabled
  - account A on client-VM-A, account B on client-VM-B
  - client-to-client  = A and B on the SAME protocol inbound
  - cross-inbound     = A on protocol X, B on protocol Y (cross-protocol; the
    nftables gate is IP/inbound-level, so this exercises the same code path)

Tunnel IPs are deterministic (radius.go computeVpnClientIP / vpnrange.go):
  IP = 10.<base>.<inboundId>.<2 + clientIndex>, base: l2tp=0 pptp=1 ovpn-udp=2 ovpn-tcp=3
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import ikev2_certs
from .model import JobResult, SubTest, Status, PHASE_SETUP
from .panel import Panel

# protocol base octet for the 10.<base>.<id>.<host> tunnel address
BASE = {"l2tp": 0, "pptp": 1, "ovpn-udp": 2, "ovpn-tcp": 3, "openconnect": 4,
        "sstp": 5, "ikev2": 6, "wg-c": 7}

PSK = "TestPSK-9182"  # L2TP/IPsec pre-shared key
IKEV2_PSK = "TestIkev2PSK-7f3a91"  # IKEv2 psk-mode shared key (single-account inbound)
# Distinct IKE server identity (IDr) for the eap-tls inbound. The always-present primary
# eap-mschapv2 inbound presents id=server_ip; two EAP conns with the SAME server id on the
# ONE shared charon can't be disambiguated (an EAP initiator looks identical until the
# method is negotiated, so charon picks eap-mschapv2 first and the eap-tls client rejects
# the MSCHAPv2 offer). Giving eap-tls its own IDr makes charon route to it by identity.
IKEV2_EAPTLS_ID = "ikev2-eaptls.vpn"

# User Limit (devices per account). All three protocols run at K=2 so the User
# Limit Strategy test can drive a 3rd device past the cap (needs the 3rd client
# VM). K=2 also keeps the per-account block allocator + source-IP routing on the
# hot path for every protocol.
L2TP_USER_LIMIT = 2
OVPN_USER_LIMIT = 2
PPTP_USER_LIMIT = 2
OC_USER_LIMIT = 2
SSTP_USER_LIMIT = 2
IKEV2_USER_LIMIT = 2
# WireGuard (C): gateway model. ONE keypair per account; the User Limit sizes the account's
# aligned IP block (rounded up to a power of two), and the single config's Address is that
# whole block (e.g. 6 -> a /29 of 8 addresses) which a router hands out to its LAN. 6 -> /29.
# Per-device tests (user-limit 2nd device / multi-user-total / strategy) are Not Applicable
# (one keypair can't split into distinct simultaneous device IPs — the /29 IS the block).
WGC_USER_LIMIT = 6

# ---- MTProto Proxy -----------------------------------------------------------
# 8443, not 443: the panel itself may hold 443, and MTProto needs a real TCP port
# of its own (there is no tunnel to share). FakeTLS plausibility does not matter to
# the prober, which checks the ServerHello HMAC rather than a browser's opinion.
MTPROTO_PORT = 8443
MTPROTO_TLS_DOMAIN = "www.google.com"
# 3 distinct client IPs per account. telemt enforces this itself (user_max_unique_ips)
# by refusing the excess device: there is no evict-oldest strategy to choose.
MTPROTO_USER_LIMIT = 3
# Fixed per-account secrets so the harness can build the client-facing shapes without
# reading them back. Real deployments have the panel mint these.
_MT_SECRET = ["00112233445566778899aabbccddeeff",
              "ffeeddccbbaa99887766554433221100"]


def _mt_client(acct: Account, idx: int, modes=("classic", "secure", "tls")) -> dict:
    """An mtproto client as the panel API expects it.

    Identity is the EMAIL (there is no username: the wg-c model); the credential is
    `secret`. Modes / FakeTLS domain / User Limit / ad tag / external proxy are all
    PER CLIENT, so they live here rather than on the inbound.

    `id` is still sent because the panel's shared client plumbing is id-keyed; it
    mirrors the email exactly, the way wg-c does it.
    """
    return {"id": acct.email, "email": acct.email, "secret": _MT_SECRET[idx],
            "enable": True,
            "modeClassic": "classic" in modes,
            "modeSecure": "secure" in modes,
            "modeTls": "tls" in modes,
            "tlsDomain": MTPROTO_TLS_DOMAIN,
            "adtagEnable": False, "adtag": "",
            "userLimit": MTPROTO_USER_LIMIT,
            "externalProxy": [],
            "expiryTime": 0, "totalGB": 0, "limitIp": 0,
            "tgId": "", "subId": "", "comment": "", "reset": 0}


def _mt_secret_shapes(base: str) -> dict:
    """The same 16-byte secret in each client-facing shape. The prefix is what tells
    the client (and telemt) which transport to speak:
      classic -> bare, secure -> "dd"+secret, tls -> "ee"+secret+hex(domain)."""
    return {
        "classic": base,
        "secure": "dd" + base,
        "tls": "ee" + base + MTPROTO_TLS_DOMAIN.encode().hex(),
    }

# Ports for the SECOND same-protocol inbound (protocols.py multi-inbound test).
# Distinct from the primary ports (openvpn udp 1194 / tcp 1443, l2tp 1701, pptp
# 1723) and from each other so the panel's port-uniqueness check passes. NOTE:
# xl2tpd/pptpd each bind ONE fixed port (1701/1723) and serve every inbound —
# differentiated by account -> RADIUS -> IP range — so for l2tp/pptp this port is
# only a unique label; only openvpn actually listens on its own per-inbound port.
SECOND_PORTS = {
    "openvpn":     {"udp": 1195, "tcp": 1444},
    "l2tp":        {"udp": 1799},
    "pptp":        {"udp": 1798},
    "openconnect": {"udp": 4444},
    "sstp":        {"udp": 8443},
    # IKEv2 shares ONE strongSwan charon bound to UDP 500/4500 for EVERY inbound, so
    # this port is only a unique DB label (like l2tp/pptp above); the 2nd inbound is
    # distinguished by its own /16-block accounts via RADIUS, not by a distinct port.
    "ikev2":       {"udp": 4500},
    # WireGuard listens on its OWN per-inbound UDP port (a kernel wgc<id> interface),
    # so this really binds a distinct listener (like openvpn/sstp, unlike l2tp/pptp).
    "wg-c":       {"udp": 51821},
}

# Nominal DB port labels for the EXTRA ikev2 auth-mode inbounds (psk / eap-tls).
# Like SECOND_PORTS["ikev2"], these are unique labels only — the one shared charon
# binds 500/4500 for every ikev2 inbound; each is distinguished by its own account
# block, not by a distinct listener. Distinct from every other inbound's port.
IKEV2_EXTRA_PORTS = {"psk": 4501, "eap-tls": 4502}
# Devices-per-account for the psk/eap-tls inbounds. K=2 so each mode runs the full
# User-Limit / strategy / multi-user-total / termination suite against the rbridge sweep,
# not just a connect smoke. The shared charon admits multiple SAs per identity (proven
# by the eap-mschapv2 K=2 test), so the 2 devices share the single account.
IKEV2_EXTRA_USER_LIMIT = 2


def build_second_inbound(panel: Panel, proto: str) -> Inbound:
    """Create a SECOND inbound of `proto` on a distinct port + IP pool with its own
    single account (index 0, user_limit=1), for the multi-inbound-same-proto E2E
    test (protocols.py). Returns the Inbound. Raises on panel error (the caller
    treats an inability to create a 2nd same-proto inbound as a product FAIL).
    Reuses the exact settings shapes the primary inbounds are built with above."""
    ports = SECOND_PORTS[proto]
    acct = _acct(proto + "2", 0)   # distinct emails: ovpn2a@t / l2tp2a@t / pptp2a@t
    if proto == "openvpn":
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": ports["tcp"],
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-openvpn-2", ports["udp"], "openvpn", settings)
        iid = inb["id"]
        return Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=ports["udp"],
            tcp_port=ports["tcp"], accounts={"A": acct},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"), user_limit=1)
    if proto == "l2tp":
        settings = {
            "ipsecEnable": True, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-l2tp-2", ports["udp"], "l2tp", settings)
        return Inbound(
            protocol="l2tp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, psk=PSK, user_limit=1)
    if proto == "pptp":
        settings = {
            "clientToClient": True, "crossInbound": True,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-pptp-2", ports["udp"], "pptp", settings)
        return Inbound(
            protocol="pptp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "openconnect":
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-openconnect-2", ports["udp"], "openconnect", settings)
        return Inbound(
            protocol="openconnect", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "sstp":
        # accel-ppp listens on its OWN per-inbound port (like openvpn/ocserv, unlike
        # xl2tpd/pptpd), so this 2nd inbound really binds a distinct SSTP/TLS port.
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-sstp-2", ports["udp"], "sstp", settings)
        return Inbound(
            protocol="sstp", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
    if proto == "ikev2":
        # The 2nd inbound is served by the SAME shared charon (bound to 500/4500); its
        # port is a nominal label. Its own generated cert/CA is captured so the client
        # can trust it (clients/ikev2.py accumulates every inbound's CA in x509ca/).
        cert = panel.generate_ikev2_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-mschapv2", "serverAddr": "",
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"], "caCert": cert["caCert"],
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-2", ports["udp"], "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1,
            ca_cert=cert.get("caCert", ""), server_addr="")
    if proto == "wg-c":
        # A distinct kernel wgc<id> interface on its own UDP port + 10.7 /24 pool,
        # single account (K=1). Keys are server-minted; fetch its device config too.
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-wgc-2", ports["udp"], "wg-c", settings)
        second = Inbound(
            protocol="wg-c", inbound_id=inb["id"], udp_port=ports["udp"],
            tcp_port=0, accounts={"A": acct}, user_limit=1)
        _fetch_wg_configs(panel, second)
        return second
    raise ValueError(proto)


def build_ikev2_extra(panel: Panel, server_ip: str, mode: str) -> Inbound:
    """Create an EXTRA ikev2 inbound for a NON-DEFAULT auth mode (psk | eap-tls).
    Both are SINGLE-account inbounds served by the same shared charon; the backend
    draws each device a tunnel IP from a whole-block charon pool and a reconcile
    sweep attributes usage + enforces the User Limit (web/service/ikev2.go). Returns
    the Inbound carrying whatever client-side credential the mode needs. Raises on
    panel error (or eap-tls cert-mint failure), which the caller records as a subtest
    ERROR without sinking the rest of setup.

    Nominal port only (charon owns 500/4500 for all ikev2 inbounds). K=2 so each mode
    runs the full single-account suite (User-Limit + strategy + multi-user-total +
    account-usage/termination) against the rbridge sweep, not just a connect smoke."""
    port = IKEV2_EXTRA_PORTS[mode]
    if mode == "psk":
        acct = _acct("ik2psk", 0)   # distinct email -> its own routing block
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "psk", "psk": IKEV2_PSK, "serverAddr": "",
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_EXTRA_USER_LIMIT,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-psk", port, "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=port, tcp_port=0,
            accounts={"A": acct}, user_limit=IKEV2_EXTRA_USER_LIMIT,
            auth_mode="psk", psk=IKEV2_PSK, server_addr="")
    if mode == "eap-tls":
        acct = _acct("ik2tls", 0)
        # Distinct IKE server identity so the shared charon routes this conn by IDr (not
        # by auth method) — it co-resides with the primary eap-mschapv2 inbound, another
        # EAP conn, and both would otherwise present id=server_ip and collide.
        # One harness CA signs the server leaf (dNSName SAN = that identity, IP SAN =
        # server_ip) AND the client leaf. inbound.caCert = that CA: charon validates the
        # client cert against it, and the client trusts the server leaf via the same CA.
        certs = ikev2_certs.mint(server_ip, acct.email, server_id=IKEV2_EAPTLS_ID)
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-tls", "serverAddr": IKEV2_EAPTLS_ID, "tlsUseFile": False,
            "certificate": certs.server_cert, "key": certs.server_key,
            "caCert": certs.ca_cert,
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_EXTRA_USER_LIMIT,
            "clients": [_dict_client(acct)],
        }
        inb = panel.add_inbound("test-ikev2-eap-tls", port, "ikev2", settings)
        return Inbound(
            protocol="ikev2", inbound_id=inb["id"], udp_port=port, tcp_port=0,
            accounts={"A": acct}, user_limit=IKEV2_EXTRA_USER_LIMIT,
            auth_mode="eap-tls",
            server_addr=IKEV2_EAPTLS_ID,    # -> client remote id = IDr (clients/ikev2.py)
            ca_cert=certs.ca_cert,          # client's server-trust anchor (== inbound caCert)
            client_cert=certs.client_cert,  # client leaf pushed to the client VM
            client_key=certs.client_key,
            client_id=certs.client_id)      # rfc822 SAN the client sets as `local id`
    raise ValueError(mode)


@dataclass
class Account:
    user: str
    password: str
    email: str
    index: int      # zero-based position in clients[]


@dataclass
class Inbound:
    protocol: str          # openvpn | l2tp | pptp
    inbound_id: int
    udp_port: int
    tcp_port: int          # openvpn only; 0 otherwise
    accounts: dict         # {"A": Account, "B": Account}
    psk: str = ""          # l2tp ipsec
    ovpn_udp: str = ""     # exported .ovpn profile text (openvpn)
    ovpn_tcp: str = ""
    user_limit: int = 1    # devices-per-account (User Limit feature); >1 = block mode
    ca_cert: str = ""      # ikev2: PEM CA the CLIENT must trust (server presents a leaf signed by it)
    server_addr: str = ""  # ikev2: the cert SAN the client sets as `remote id` ("" -> use server IP)
    auth_mode: str = "eap-mschapv2"  # ikev2: eap-mschapv2 (default) | psk | eap-tls
    client_cert: str = ""  # ikev2 eap-tls: client leaf PEM to push to the client VM
    client_key: str = ""   # ikev2 eap-tls: client leaf key PEM to push to the client VM
    client_id: str = ""    # ikev2 eap-tls: the client's EAP identity (rfc822 SAN) -> `local id`
    # wgc: {which: [ {deviceIndex, ip, publicKey, config}, ... ]} — the panel-minted
    # per-device client configs, fetched from the wgc-configs endpoint after build.
    wg_configs: dict = field(default_factory=dict)

    # mtproto: {which: {mode: secret_hex}}, the per-account secret in each of the
    # three client-facing shapes (bare / dd… / ee…+domain), built at inbound
    # creation. MTProto has no config file to fetch: the secret IS the credential.
    mt_secrets: dict = field(default_factory=dict)

    # mtproto: {which: [mode, ...]}, the modes each account is ALLOWED, which the
    # proxy enforces per account via [access.user_modes]. Accounts deliberately
    # differ so the suite can tell per-account enforcement from per-inbound.
    mt_modes: dict = field(default_factory=dict)

    def client_ip(self, which: str, transport: str = "udp", device: int = 0) -> str:
        """Tunnel IP for account A/B on this inbound. With user_limit K>1 each
        account owns an aligned K-block: host base = (index+1)*K, device d = base+d
        (mirrors Go vpnAccountDeviceIP). K==1 keeps the legacy 2+index host."""
        if self.protocol == "mtproto":
            # MTProto is a relay: the panel assigns no address, and the client keeps
            # its own IP. Returning a plausible-looking 10.x here would be a lie the
            # routing/dns-leak checks would then act on, so fail loudly instead.
            raise AssertionError(
                "mtproto has no tunnel IP: client_ip() must not be called for it")
        acct = self.accounts[which]
        if self.protocol == "openvpn":
            base = BASE["ovpn-tcp"] if transport == "tcp" else BASE["ovpn-udp"]
        else:
            base = BASE[self.protocol]
        if self.protocol == "wg-c" and self.user_limit > 1:
            # gateway model: one aligned power-of-two block per account; its IP is the
            # block's first address (nextPow2 rounding, mirrors Go wgcAccountBlock).
            bs = 1
            while bs < self.user_limit:
                bs <<= 1
            return f"10.{base}.{self.inbound_id}.{(acct.index + 1) * bs}"
        if self.user_limit > 1:
            host = (acct.index + 1) * self.user_limit + device
        else:
            host = 2 + acct.index
        return f"10.{base}.{self.inbound_id}.{host}"


@dataclass
class ServerConfig:
    server_ip: str
    inbounds: dict = field(default_factory=dict)   # protocol -> Inbound
    # NON-DEFAULT ikev2 auth mode -> its dedicated single-account Inbound (psk / eap-tls).
    # Kept OUT of `inbounds` on purpose: the primary suite, routing rules + translation
    # assert, bulk-ops and backup all iterate `inbounds`, so extras stay invisible to
    # them and only the ikev2 phase's per-mode block (protocols.py) consumes these.
    ikev2_extra: dict = field(default_factory=dict)


def _acct(prefix: str, idx: int) -> Account:
    letter = "A" if idx == 0 else "B"
    return Account(user=f"{prefix}{letter.lower()}",
                   password=f"Pw-{prefix}{letter}-9k",
                   email=f"{prefix}{letter.lower()}@t",
                   index=idx)


def run(panel: Panel, server_ip: str, cfg: dict, result: JobResult,
        log=None) -> ServerConfig | None:
    """Build inbounds/accounts/outbound/routing. Returns ServerConfig, or None
    if a fatal setup error occurred (subtests record the detail)."""
    log = log or (lambda *_: None)
    phase = result.phase(PHASE_SETUP)
    sc = ServerConfig(server_ip=server_ip)

    # IKEv2 (strongSwan charon) and L2TP/IPsec (libreswan pluto) both bind UDP 500/4500 —
    # only ONE IKE daemon can own those ports on a host. They are mutually exclusive on a
    # single IP by design. So when the ikev2 phase is explicitly selected, run L2TP raw-only
    # (no IPsec) so charon can bind 500/4500; otherwise L2TP keeps its raw+IPsec config.
    _sel = cfg.get("_selected")
    _ikev2_sel = _sel is not None and "ikev2" in _sel

    # IKEv2 auth modes to exercise (config [ikev2] modes). Absent key -> the historical
    # single mode, so existing runs are unchanged. eap-mschapv2 is the primary inbound
    # built below; every OTHER listed mode gets its own extra single-account inbound.
    _ikev2_modes = (cfg.get("ikev2") or {}).get("modes") or ["eap-mschapv2"]
    _ikev2_extra_modes = [m for m in _ikev2_modes if m != "eap-mschapv2"]

    # ---- OpenVPN inbound ------------------------------------------------
    log("-> creating openvpn inbound (certs + 2 accounts, ciphers=all)...")
    ov = phase.add(SubTest("openvpn-inbound"))
    try:
        certs = panel.generate_openvpn_certs()
        settings = {
            "udpEnable": True, "tcpEnable": True,
            "tcpPort": 1443,
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "caCert": certs["caCert"], "caKey": certs["caKey"],
            "serverCert": certs["serverCert"], "serverKey": certs["serverKey"],
            "tlsCrypt": certs["tlsCrypt"],
            "cipherMode": "all",
            # AEAD (new) + a default-provider CBC (old); both testable without
            # the OpenSSL legacy provider.
            "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305", "AES-256-CBC"],
            "clientToClient": True,
            "crossInbound": True,
            "userLimit": OVPN_USER_LIMIT,  # exercise the connect-hook block allocator
            "clients": [
                _dict_client(_acct("ovpn", 0)),
                _dict_client(_acct("ovpn", 1)),
            ],
        }
        inb = panel.add_inbound("test-openvpn", 1194, "openvpn", settings)
        iid = inb["id"]
        sc.inbounds["openvpn"] = Inbound(
            protocol="openvpn", inbound_id=iid, udp_port=1194, tcp_port=1443,
            accounts={"A": _acct("ovpn", 0), "B": _acct("ovpn", 1)},
            ovpn_udp=panel.download_ovpn(iid, "udp"),
            ovpn_tcp=panel.download_ovpn(iid, "tcp"),
            user_limit=OVPN_USER_LIMIT,
        )
        ov.status = Status.PASS
        ov.detail = f"inbound {iid}, udp 1194 / tcp 1443, 2 accounts, ciphers all"
    except Exception as e:  # noqa: BLE001
        ov.status = Status.ERROR
        ov.detail = str(e)[:300]

    log(f"-> openvpn-inbound [{ov.status.value}] {ov.detail}")

    # ---- L2TP inbound ---------------------------------------------------
    log("-> creating l2tp inbound (%s, 2 accounts)..." % ("raw-only, ikev2 owns 500/4500" if _ikev2_sel else "raw+ipsec"))
    l2 = phase.add(SubTest("l2tp-inbound"))
    try:
        settings = {
            "ipsecEnable": not _ikev2_sel, "ipsecPsk": PSK, "allowRaw": True,
            "clientToClient": True, "crossInbound": True,
            "userLimit": L2TP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("l2tp", 0)),
                        _dict_client(_acct("l2tp", 1))],
        }
        inb = panel.add_inbound("test-l2tp", 1701, "l2tp", settings)
        iid = inb["id"]
        sc.inbounds["l2tp"] = Inbound(
            protocol="l2tp", inbound_id=iid, udp_port=1701, tcp_port=0,
            accounts={"A": _acct("l2tp", 0), "B": _acct("l2tp", 1)}, psk=PSK,
            user_limit=L2TP_USER_LIMIT,
        )
        l2.status = Status.PASS
        l2.detail = f"inbound {iid}, {'raw-only (ikev2 owns 500/4500)' if _ikev2_sel else 'raw+ipsec, psk set'}, 2 accounts"
    except Exception as e:  # noqa: BLE001
        l2.status = Status.ERROR
        l2.detail = str(e)[:300]

    log(f"-> l2tp-inbound [{l2.status.value}] {l2.detail}")

    # ---- PPTP inbound ---------------------------------------------------
    log("-> creating pptp inbound (2 accounts)...")
    pp = phase.add(SubTest("pptp-inbound"))
    try:
        settings = {
            "clientToClient": True, "crossInbound": True,
            "userLimit": PPTP_USER_LIMIT,  # exercise the per-account block allocator
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "clients": [_dict_client(_acct("pptp", 0)),
                        _dict_client(_acct("pptp", 1))],
        }
        inb = panel.add_inbound("test-pptp", 1723, "pptp", settings)
        iid = inb["id"]
        sc.inbounds["pptp"] = Inbound(
            protocol="pptp", inbound_id=iid, udp_port=1723, tcp_port=0,
            accounts={"A": _acct("pptp", 0), "B": _acct("pptp", 1)},
            user_limit=PPTP_USER_LIMIT,
        )
        pp.status = Status.PASS
        pp.detail = f"inbound {iid}, 2 accounts"
    except Exception as e:  # noqa: BLE001
        pp.status = Status.ERROR
        pp.detail = str(e)[:300]

    log(f"-> pptp-inbound [{pp.status.value}] {pp.detail}")

    # ---- OpenConnect inbound --------------------------------------------
    log("-> creating openconnect inbound (self-signed cert, 2 accounts)...")
    oc = phase.add(SubTest("openconnect-inbound"))
    try:
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": OC_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("ocserv", 0)),
                        _dict_client(_acct("ocserv", 1))],
        }
        inb = panel.add_inbound("test-openconnect", 4443, "openconnect", settings)
        iid = inb["id"]
        sc.inbounds["openconnect"] = Inbound(
            protocol="openconnect", inbound_id=iid, udp_port=4443, tcp_port=0,
            accounts={"A": _acct("ocserv", 0), "B": _acct("ocserv", 1)},
            user_limit=OC_USER_LIMIT,
        )
        oc.status = Status.PASS
        oc.detail = f"inbound {iid}, port 4443 (TLS+DTLS), 2 accounts"
    except Exception as e:  # noqa: BLE001
        oc.status = Status.ERROR
        oc.detail = str(e)[:300]

    log(f"-> openconnect-inbound [{oc.status.value}] {oc.detail}")

    # ---- SSTP inbound ---------------------------------------------------
    # accel-ppp (PPP-over-TLS): self-signed TLS cert like openconnect, but PPP-family
    # RADIUS/accounting like pptp. Port 443 (the SSTP default the native Windows
    # client expects). The cert helper is shared with ocserv (same ECDSA self-signed).
    log("-> creating sstp inbound (accel-ppp, self-signed TLS cert, 2 accounts)...")
    ss = phase.add(SubTest("sstp-inbound"))
    try:
        cert = panel.generate_ocserv_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1400,
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": SSTP_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("sstp", 0)),
                        _dict_client(_acct("sstp", 1))],
        }
        inb = panel.add_inbound("test-sstp", 443, "sstp", settings)
        iid = inb["id"]
        sc.inbounds["sstp"] = Inbound(
            protocol="sstp", inbound_id=iid, udp_port=443, tcp_port=0,
            accounts={"A": _acct("sstp", 0), "B": _acct("sstp", 1)},
            user_limit=SSTP_USER_LIMIT,
        )
        ss.status = Status.PASS
        ss.detail = f"inbound {iid}, port 443 (SSTP/TLS), 2 accounts"
    except Exception as e:  # noqa: BLE001
        ss.status = Status.ERROR
        ss.detail = str(e)[:300]

    log(f"-> sstp-inbound [{ss.status.value}] {ss.detail}")

    # ---- IKEv2 inbound --------------------------------------------------
    # IKEv2/IPsec via a SINGLE shared strongSwan charon (bound to UDP 500/4500) that
    # serves every ikev2 inbound. Auth = EAP-MSCHAPv2 (server-authoritative RADIUS,
    # like ocserv). The server presents a self-signed leaf; the CLIENT must trust the
    # returned caCert — capture it on the Inbound so clients/ikev2.py can load it into
    # swanctl's x509ca dir. serverAddr left empty => leaf SAN = detected server IP, so
    # the client's `remote id = <server_ip>` matches. Port 500 is a nominal label.
    log("-> creating ikev2 inbound (shared charon, EAP-MSCHAPv2, self-signed cert+CA, 2 accounts)...")
    ik = phase.add(SubTest("ikev2-inbound"))
    try:
        cert = panel.generate_ikev2_cert()
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8",
            "authMode": "eap-mschapv2", "serverAddr": "",
            "tlsUseFile": False,
            "certificate": cert["certificate"], "key": cert["key"], "caCert": cert["caCert"],
            "clientToClient": True, "crossInbound": True,
            "userLimit": IKEV2_USER_LIMIT,  # exercise the RADIUS per-account block allocator
            "clients": [_dict_client(_acct("ikev2", 0)),
                        _dict_client(_acct("ikev2", 1))],
        }
        inb = panel.add_inbound("test-ikev2", 500, "ikev2", settings)
        iid = inb["id"]
        sc.inbounds["ikev2"] = Inbound(
            protocol="ikev2", inbound_id=iid, udp_port=500, tcp_port=0,
            accounts={"A": _acct("ikev2", 0), "B": _acct("ikev2", 1)},
            user_limit=IKEV2_USER_LIMIT, ca_cert=cert.get("caCert", ""), server_addr="")
        ik.status = Status.PASS
        ik.detail = f"inbound {iid}, IKEv2/EAP (charon 500/4500), 2 accounts"
    except Exception as e:  # noqa: BLE001
        ik.status = Status.ERROR
        ik.detail = str(e)[:300]

    log(f"-> ikev2-inbound [{ik.status.value}] {ik.detail}")

    # ---- IKEv2 extra auth-mode inbounds (psk / eap-tls) -----------------
    # One dedicated single-account inbound per non-default mode, served by the SAME
    # shared charon. Built only when ikev2 is in play (_ikev2_sel: full run or
    # --tests ikev2) AND the primary inbound exists AND extra modes are configured.
    # Stored in sc.ikev2_extra so the primary suite/routing/bulk/backup are untouched;
    # protocols.py's ikev2 phase runs a per-mode connect + data-plane block on each.
    if _ikev2_sel and "ikev2" in sc.inbounds and _ikev2_extra_modes:
        for mode in _ikev2_extra_modes:
            log(f"-> creating ikev2 {mode} inbound (single account)...")
            ex = phase.add(SubTest(f"ikev2-{mode}-inbound"))
            try:
                extra = build_ikev2_extra(panel, server_ip, mode)
                sc.ikev2_extra[mode] = extra
                ex.status = Status.PASS
                ex.detail = f"inbound {extra.inbound_id}, ikev2/{mode} (port {extra.udp_port}), 1 account"
            except Exception as e:  # noqa: BLE001
                ex.status = Status.ERROR
                ex.detail = str(e)[:300]
            log(f"-> ikev2-{mode}-inbound [{ex.status.value}] {ex.detail}")

    # ---- WireGuard (C) inbound ------------------------------------------
    # In-kernel WireGuard driven by wgctrl (protocol id `wgc`, base 10.7/16). No
    # RADIUS: a peer's public key is its credential, so the rbridge sweep bills usage +
    # enforces quota/disable, and the panel mints one keypair per account. Gateway model:
    # the User Limit (6) sizes each account's aligned block (-> a /29), and its single
    # config addresses that whole block. After build we fetch each account's config.
    log("-> creating wgc inbound (kernel wireguard, gateway /29, 2 accounts, user-limit 6)...")
    wgs = phase.add(SubTest("wgc-inbound"))
    try:
        settings = {
            "dns1": "1.1.1.1", "dns2": "8.8.8.8", "mtu": 1420,
            "pskEnable": False,
            "clientToClient": True, "crossInbound": True,
            "userLimit": WGC_USER_LIMIT,
            "clients": [_dict_client(_acct("wg-c", 0)),
                        _dict_client(_acct("wg-c", 1))],
        }
        inb = panel.add_inbound("test-wgc", 51820, "wg-c", settings)
        iid = inb["id"]
        wg_ib = Inbound(
            protocol="wg-c", inbound_id=iid, udp_port=51820, tcp_port=0,
            accounts={"A": _acct("wg-c", 0), "B": _acct("wg-c", 1)},
            user_limit=WGC_USER_LIMIT)
        _fetch_wg_configs(panel, wg_ib)
        sc.inbounds["wg-c"] = wg_ib
        n_cfg = sum(len(v) for v in wg_ib.wg_configs.values())
        wgs.status = Status.PASS
        wgs.detail = f"inbound {iid}, udp 51820, 2 accounts (gateway /29), {n_cfg} configs"
    except Exception as e:  # noqa: BLE001
        wgs.status = Status.ERROR
        wgs.detail = str(e)[:300]

    log(f"-> wgc-inbound [{wgs.status.value}] {wgs.detail}")

    # ---- MTProto Proxy inbound ------------------------------------------
    # telemt (protocol id `mtproto`). The ODD ONE: a userspace relay, so there is NO
    # tunnel, NO 10.x block, NO BASE entry and NO RADIUS. All three connection modes
    # are served at once by the single inbound: the client picks by its secret's
    # prefix: so one inbound covers the classic/secure/tls phases. Ad tag stays OFF
    # so this inbound egresses through Xray (the two are mutually exclusive; with the
    # tag on, middle-proxy mode pins egress to a direct path).
    log("-> creating mtproto inbound (telemt, all 3 modes, 2 accounts, user-limit 3)...")
    mts = phase.add(SubTest("mtproto-inbound"))
    try:
        # A: all three modes. B: SECURE ONLY: deliberately different, so the suite can
        # prove per-account enforcement rather than just per-inbound. The listener ends
        # up allowing all three (the union), so B being refused on classic/tls can only
        # come from [access.user_modes]; if that patch ever stopped working, B would
        # start passing modes it does not hold and the mode-restriction subtest fails.
        settings = {
            "clients": [_mt_client(_acct("mtproto", 0), 0),
                        _mt_client(_acct("mtproto", 1), 1, modes=("secure",))],
        }
        inb = panel.add_inbound("test-mtproto", MTPROTO_PORT, "mtproto", settings)
        iid = inb["id"]
        mt_ib = Inbound(
            protocol="mtproto", inbound_id=iid, udp_port=0, tcp_port=MTPROTO_PORT,
            accounts={"A": _acct("mtproto", 0), "B": _acct("mtproto", 1)},
            user_limit=MTPROTO_USER_LIMIT)
        # The panel does not mint these: we supplied them above, so build the
        # client-facing shapes locally rather than fetching them back.
        mt_ib.mt_secrets = {
            "A": _mt_secret_shapes(_MT_SECRET[0]),
            "B": _mt_secret_shapes(_MT_SECRET[1]),
        }
        # Which modes each account HOLDS, so the suite can assert both directions:
        # an allowed mode must work, and a mode the account does not hold must be
        # refused even though the listener accepts it for the other account.
        mt_ib.mt_modes = {"A": ["classic", "secure", "tls"], "B": ["secure"]}
        sc.inbounds["mtproto"] = mt_ib
        mts.status = Status.PASS
        mts.detail = (f"inbound {iid}, tcp {MTPROTO_PORT}, 2 accounts "
                      f"(A: classic+secure+tls, B: secure-only: per-client modes), "
                      f"tls_domain {MTPROTO_TLS_DOMAIN}")
    except Exception as e:  # noqa: BLE001
        mts.status = Status.ERROR
        mts.detail = str(e)[:300]

    log(f"-> mtproto-inbound [{mts.status.value}] {mts.detail}")

    # ---- source-IP routing rules (built-in outbounds, no external link) ----
    # Prove Xray routes by source IP using the two outbounds every config already
    # ships: `direct` (freedom) and `blocked` (blackhole). Author by email (the
    # panel auto-translates email -> source IP): A-accounts -> freedom (reach the
    # internet), B-accounts -> blackhole (cut off). The per-protocol `routing`
    # check then proves the split deterministically from the CONTRAST — same
    # protocol, adjacent tunnel IPs, only the rule differs — with no external
    # outbound and no exit-IP compare (which false-fails whenever the outbound and
    # the test host happen to share an egress IP).
    log("-> adding source-IP routing rules (A->freedom, B->blackhole)...")
    route = phase.add(SubTest("routing-rules"))
    try:
        tmpl = panel.get_xray_template()
        routing = tmpl.setdefault("routing", {})
        rules = routing.setdefault("rules", [])
        # mtproto is excluded on purpose: these rules are email->source-IP, and the
        # panel can only translate an email whose account owns a tunnel IP. MTProto
        # assigns none (it is a relay), so its emails would stay as un-matchable
        # `user` rules: routing for it is per-INBOUND, via its socks inbound's tag.
        _routable = [ib for p, ib in sc.inbounds.items() if p != "mtproto"]
        a_emails = [ib.accounts["A"].email for ib in _routable]
        b_emails = [ib.accounts["B"].email for ib in _routable]
        # insert at the front so these win over the default catch-all / geoip rules
        rules.insert(0, {"type": "field", "outboundTag": "direct", "user": a_emails})
        rules.insert(1, {"type": "field", "outboundTag": "blocked", "user": b_emails})
        panel.update_xray_template(tmpl)
        route.status = Status.PASS
        route.detail = f"A->freedom {a_emails}, B->blackhole {b_emails}"
        route.log = (f"freedom (direct):  {', '.join(a_emails)}\n"
                     f"blackhole (blocked): {', '.join(b_emails)}")
    except Exception as e:  # noqa: BLE001
        route.status = Status.ERROR
        route.detail = str(e)[:300]

    log(f"-> routing-rules [{route.status.value}] {route.detail}")

    # ---- assert email->source-IP translation ---------------------------
    # The blackhole rule is the meaningful one: verify the panel translated the
    # B-account emails into a source-IP rule bound to `blocked`. (B is a client on
    # every inbound; openvpn B appears at both its 10.2/10.3 transport IPs.)
    log("-> verifying panel translated B emails -> source-IP (blackhole)...")
    trans = phase.add(SubTest("routing-translation"))
    try:
        want_ips = set()
        for ib in sc.inbounds.values():
            if ib.protocol == "mtproto":
                continue  # no tunnel IP to translate: excluded from these rules above
            if ib.protocol == "openvpn":
                want_ips.add(ib.client_ip("B", "udp"))
                want_ips.add(ib.client_ip("B", "tcp"))
            else:
                want_ips.add(ib.client_ip("B"))
        conf = panel.get_config_json()
        src_seen = set()
        for r in conf.get("routing", {}).get("rules", []):
            if r.get("outboundTag") == "blocked":
                for s in r.get("source", []) or []:
                    src_seen.add(s)
        # A source may be a bare IP (K==1) or a CIDR block (User Limit K>1) — a
        # want IP counts as a hit if it equals or is contained in a seen source.
        import ipaddress as _ip
        def _covers(src: str, ip: str) -> bool:
            try:
                return _ip.ip_address(ip) in _ip.ip_network(src, strict=False)
            except ValueError:
                return src == ip
        hit = {w for w in want_ips if any(_covers(s, w) for s in src_seen)}
        trans.log = f"expected any of {sorted(want_ips)}\nsaw blackhole source {sorted(src_seen)}"
        if hit:
            trans.status = Status.PASS
            trans.detail = f"panel translated B user->source (blackhole); matched {sorted(hit)}"
        else:
            trans.status = Status.FAIL
            trans.detail = "no blackhole source-IP rule found for B accounts"
    except Exception as e:  # noqa: BLE001
        trans.status = Status.ERROR
        trans.detail = str(e)[:300]

    # ---- xray actually running with the new config ---------------------
    # Pre-inbound xray may be idle/error; now that inbounds + routing exist it
    # must run, or all tproxy->xray->internet + routing tests will fail. Restart
    # and verify, capturing logs so a backend xray failure is visible here.
    log("-> restarting xray + verifying it runs with the new config...")
    xr = phase.add(SubTest("xray-running"))
    try:
        import time as _t
        panel.restart_core("xray")
        _t.sleep(3)
        cores = {c.get("name"): c for c in panel.core_status().get("cores", [])}
        xstate = (cores.get("xray") or {}).get("state", "?")
        xr.log = f"state={xstate}\n\n== xray logs ==\n" + _safe(panel, "xray")
        if xstate in ("running", "idle"):
            xr.status = Status.PASS
            xr.detail = f"xray {xstate}"
        else:
            xr.status = Status.FAIL
            xr.detail = f"xray not running (state={xstate}) — internet/routing will fail"
        log(f"-> xray-running [{xr.status.value}] {xr.detail}")
    except Exception as e:  # noqa: BLE001
        xr.status = Status.ERROR
        xr.detail = str(e)[:300]

    # Fatal only if we couldn't build any inbound. Every protocol must be listed:
    # a protocol missing here is invisible to this check, so a run where only IT
    # succeeded would still be declared a total failure and throw the good inbound
    # away. ("wg-c" was missing until now: mtproto would have hit the same trap.)
    if all(p not in sc.inbounds for p in ("openvpn", "l2tp", "pptp", "openconnect",
                                          "sstp", "ikev2", "wg-c", "mtproto")):
        return None
    return sc


def _safe(panel: Panel, core: str) -> str:
    try:
        return panel.core_logs(core)
    except Exception:  # noqa: BLE001
        return "(no logs)"


def _dict_client(a: Account) -> dict:
    return {"id": a.user, "password": a.password, "email": a.email, "enable": True}


def _fetch_wg_configs(panel: Panel, inbound: Inbound) -> None:
    """Populate inbound.wg_configs[which] with the panel-minted per-device client
    configs for every account. Best-effort per account (an empty list surfaces later
    as a clear 'no wireguard config' connect failure rather than a setup crash)."""
    inbound.wg_configs = {}
    for which, acct in inbound.accounts.items():
        try:
            inbound.wg_configs[which] = panel.wgc_configs(inbound.inbound_id, acct.email)
        except Exception:  # noqa: BLE001
            inbound.wg_configs[which] = []
