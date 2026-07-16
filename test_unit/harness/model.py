"""Result model shared across the harness.

A run produces one JobResult per server distro. Each JobResult holds an ordered
list of Phases; each Phase holds SubTests. Everything serialises to plain dicts
for the JSON report; the HTML report renders the same structure.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"   # deliberately not run (e.g. dependency of a failed step)
    NA = "na"       # not applicable / external dependency unavailable
    ERROR = "error" # harness/infra blew up (not a product failure)


def worst(statuses) -> Status:
    """Roll a collection of statuses up to a single verdict.

    Precedence: ERROR > FAIL > PASS > NA > SKIP. Crucially PASS outranks NA/SKIP,
    so an otherwise-green phase with one inconclusive check (e.g. a flaky
    external dns-leak service = NA) still rolls up to PASS rather than being
    dragged down. NA/SKIP only surface when nothing actually passed."""
    seen = {Status(s) for s in statuses}
    if not seen:
        return Status.SKIP
    for level in (Status.ERROR, Status.FAIL, Status.PASS, Status.NA, Status.SKIP):
        if level in seen:
            return level
    return Status.SKIP


@dataclass
class SubTest:
    name: str
    status: Status = Status.SKIP
    detail: str = ""          # one-line human summary
    log: str = ""             # full captured output for the drilldown
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Phase:
    name: str
    subtests: list = field(default_factory=list)

    def add(self, sub: SubTest) -> SubTest:
        self.subtests.append(sub)
        return sub

    @property
    def status(self) -> Status:
        return worst(s.status for s in self.subtests)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "subtests": [s.to_dict() for s in self.subtests],
        }


@dataclass
class JobResult:
    distro: str
    image: str
    phases: list = field(default_factory=list)
    started_at: str = ""      # ISO8601, stamped by orchestrator
    finished_at: str = ""
    server_ip: str = ""
    notes: str = ""           # infra-level message (e.g. "image not found -> skipped")

    def phase(self, name: str) -> Phase:
        """Get-or-create a phase by name, preserving insertion order."""
        for p in self.phases:
            if p.name == name:
                return p
        p = Phase(name)
        self.phases.append(p)
        return p

    @property
    def status(self) -> Status:
        return worst(p.status for p in self.phases)

    def to_dict(self) -> dict:
        return {
            "distro": self.distro,
            "image": self.image,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "server_ip": self.server_ip,
            "notes": self.notes,
            "phases": [p.to_dict() for p in self.phases],
        }


# Canonical phase names (kept stable so the report columns line up).
PHASE_CORE = "core-init"
PHASE_SETUP = "server-setup"
PHASE_OPENVPN = "openvpn"
PHASE_L2TP = "l2tp"
PHASE_PPTP = "pptp"
PHASE_OPENCONNECT = "openconnect"
PHASE_SSTP = "sstp"
PHASE_IKEV2 = "ikev2"                        # selection alias -> the per-mode phases below
PHASE_IKEV2_EAPMSCHAP = "ikev2-eap-mschapv2"
PHASE_IKEV2_PSK = "ikev2-psk"
PHASE_IKEV2_EAPTLS = "ikev2-eap-tls"
# Each IKEv2 auth mode is its own phase/column and runs the full applicable suite
# (eap-mschapv2 = the RADIUS path + 2-account tests; psk/eap-tls = the single-account
# rbridge-sweep path). Order = the order they run in.
IKEV2_MODE_PHASES = [PHASE_IKEV2_EAPMSCHAP, PHASE_IKEV2_PSK, PHASE_IKEV2_EAPTLS]
IKEV2_PHASE_BY_MODE = {"eap-mschapv2": PHASE_IKEV2_EAPMSCHAP,
                       "psk": PHASE_IKEV2_PSK, "eap-tls": PHASE_IKEV2_EAPTLS}
PHASE_WGC = "wg-c"                        # WireGuard (C) — kernel wireguard via wgctrl
PHASE_MTPROTO = "mtproto"                 # selection alias -> the per-mode phases below
PHASE_MTPROTO_CLASSIC = "mtproto-classic"
PHASE_MTPROTO_SECURE = "mtproto-secure"
PHASE_MTPROTO_TLS = "mtproto-tls"
# Each MTProto connection mode is its own phase/column. Unlike IKEv2's auth modes
# (which are mutually exclusive per inbound), all three MTProto modes are served by
# ONE inbound simultaneously: the client picks by its secret's prefix. So the modes
# differ only in how the client dials, and they share a single inbound.
MTPROTO_MODE_PHASES = [PHASE_MTPROTO_CLASSIC, PHASE_MTPROTO_SECURE, PHASE_MTPROTO_TLS]
MTPROTO_PHASE_BY_MODE = {"classic": PHASE_MTPROTO_CLASSIC,
                         "secure": PHASE_MTPROTO_SECURE, "tls": PHASE_MTPROTO_TLS}
# Editing an account's modes, which the three phases above cannot cover: they read a
# mode set that was fixed at inbound creation. telemt takes modes from TWO places -
# [general.modes] (process-wide, the UNION over accounts) and [access.user_modes]
# (per account), and the union only MOVES when an edit adds a mode no other account
# had. Miss the hot-reload on either and the toggle silently does nothing until the
# next restart, which is exactly what a user sees as "the backend ignores my toggle".
PHASE_MTPROTO_TOGGLE = "mtproto-toggle"
PHASE_BULK = "bulk-ops"
PHASE_BACKUP = "backup-restore"
PHASE_WARP = "warp-socks"
PHASE_RANDOM = "random-cfg"
PHASE_SYSTEMD = "systemd"
PHASE_UNINSTALL = "uninstall"

ALL_PHASES = [PHASE_CORE, PHASE_SETUP, PHASE_OPENVPN, PHASE_L2TP, PHASE_PPTP,
              PHASE_OPENCONNECT, PHASE_SSTP,
              PHASE_IKEV2_EAPMSCHAP, PHASE_IKEV2_PSK, PHASE_IKEV2_EAPTLS,
              PHASE_WGC,
              PHASE_MTPROTO_CLASSIC, PHASE_MTPROTO_SECURE, PHASE_MTPROTO_TLS,
              PHASE_MTPROTO_TOGGLE,
              PHASE_BULK, PHASE_BACKUP,
              PHASE_WARP, PHASE_RANDOM, PHASE_SYSTEMD, PHASE_UNINSTALL]
