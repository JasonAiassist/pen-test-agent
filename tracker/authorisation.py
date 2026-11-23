"""Engagement authorisation records — the contract gate for research mode.

Research mode (hypothesis-driven vulnerability chaining and unknown-flaw discovery)
is powerful and must never run outside a sanctioned engagement. This module decides,
fail-closed, whether a given scan may use research mode:

  * Lab / internal-only research (every in-scope target internal, no destructive/DoS):
    a lightweight *self-authorisation* is enough — any non-empty `authorisation`
    reference on the project. Nothing leaves the lab, so a signed contract is not
    required to experiment against targets you own.

  * External targets, destructive payloads, or DoS under research mode:
    require a *structured* authorisation record — a file `authorisations/<ref>.json`
    on the host (kept out of git) — that is unexpired, flagged to permit what the scan
    asks for (research_allowed / destructive_allowed), and whose scope covers every
    in-scope target. A free-text reference alone is refused for these.

Pure and stdlib-only; the record is loaded from disk but every decision is a pure
function of (record, scan parameters, today), so it is fully unit-tested offline.
Record schema (see docs/authorisation-example.json):
    {ref, client, contract_ref, authorised_by, expires: "YYYY-MM-DD",
     research_allowed: bool, destructive_allowed: bool,
     scope: [ "<endpoint value>" | {type,data} ], notes}
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path

import scope

ROOT = Path(__file__).resolve().parents[1]
AUTH_DIR = ROOT / "authorisations"
_REF_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def _today() -> _dt.date:
    return _dt.date.today()


def record_path(ref: str, auth_dir: Path | None = None) -> Path | None:
    """Resolve a reference to a JSON record path under auth_dir, or None.
    Only a sanitised basename is honoured (no path traversal)."""
    auth_dir = auth_dir or AUTH_DIR
    ref = (ref or "").strip()
    if not ref:
        return None
    name = ref[1:] if ref.startswith("@") else ref
    name = name[:-5] if name.endswith(".json") else name
    name = _REF_SAFE.sub("-", name)
    if not name:
        return None
    p = auth_dir / f"{name}.json"
    return p if p.is_file() else None


def parse_record(data: dict, ref: str = "") -> dict:
    """Normalise a raw record dict. Unknown/missing flags default to the safe value (False)."""
    scope_raw = data.get("scope") or []
    scope_entries = []
    for e in scope_raw:
        if isinstance(e, dict) and e.get("data"):
            scope_entries.append({"type": e.get("type") or (scope.infer_type(e["data"]) or ""),
                                  "data": str(e["data"])})
        elif isinstance(e, str) and e.strip():
            scope_entries.append({"type": scope.infer_type(e) or "", "data": e.strip()})
    return {
        "ref": str(data.get("ref") or ref or ""),
        "client": str(data.get("client") or ""),
        "contract_ref": str(data.get("contract_ref") or ""),
        "authorised_by": str(data.get("authorised_by") or ""),
        "expires": str(data.get("expires") or ""),
        "research_allowed": bool(data.get("research_allowed", False)),
        "destructive_allowed": bool(data.get("destructive_allowed", False)),
        "scope": scope_entries,
        "notes": str(data.get("notes") or ""),
        "inline": False,
    }


def load_record(cfg: dict, auth_dir: Path | None = None) -> dict | None:
    """Return a structured record (from authorisations/<ref>.json), or an inline
    self-authorisation ({inline:True}) when the project only names a free-text ref,
    or None when no authorisation reference is set at all."""
    auth_dir = auth_dir or AUTH_DIR
    ref = (cfg.get("authorisation") or "").strip()
    if not ref:
        return None
    path = record_path(ref, auth_dir)
    if path is not None:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return {"ref": ref, "inline": True, "scope": [], "research_allowed": False,
                    "destructive_allowed": False, "expires": "", "_error": "record unreadable"}
        return parse_record(data, ref=ref)
    return {"ref": ref, "inline": True, "scope": [], "research_allowed": False,
            "destructive_allowed": False, "expires": ""}


def _expired(record: dict, today: _dt.date) -> bool:
    exp = (record.get("expires") or "").strip()
    if not exp:
        return False  # no expiry set
    try:
        return _dt.date.fromisoformat(exp) < today
    except ValueError:
        return True  # an unparseable expiry is treated as expired (fail closed)


def _covers(record: dict, in_scope: list) -> list[str]:
    """Return the list of in-scope endpoint values NOT covered by the record's scope.
    Coverage is by normalised key equality, or an in-scope entry inside a scope CIDR."""
    import ipaddress

    keys, cidrs = set(), []
    for e in record.get("scope") or []:
        t, d = e.get("type"), e.get("data")
        if scope.validate_endpoint(t, d):
            continue
        keys.add(scope.norm_key(t, d))
        if t == "cidr":
            cidrs.append(ipaddress.ip_network(d, strict=False))
    uncovered = []
    for e in in_scope:
        if not isinstance(e, dict):
            continue
        t, d = e.get("type"), e.get("data")
        if scope.validate_endpoint(t, d):
            continue
        if scope.norm_key(t, d) in keys:
            continue
        covered = False
        if t in ("ip", "cidr") and cidrs:
            net = ipaddress.ip_network(d, strict=False)
            covered = any(net.subnet_of(c) for c in cidrs if c.version == net.version)
        if not covered:
            uncovered.append(d)
    return uncovered


def authorise_research(record: dict | None, *, position: str, destructive: bool,
                       dos: bool, in_scope: list, today: _dt.date | None = None) -> tuple[bool, list[str]]:
    """Decide, fail-closed, whether research mode may run. Returns (ok, reasons-if-refused)."""
    today = today or _today()
    needs_contract = position in ("external", "both") or destructive or dos
    if not needs_contract:
        # Lab / internal-only, non-destructive: a self-authorisation reference suffices.
        if record is None:
            return False, ["research mode needs at least a self-authorisation reference "
                           "(set the project's authorisation field)"]
        return True, []
    # External / destructive / DoS research demands a structured contract record.
    errs: list[str] = []
    if record is None:
        return False, ["external or destructive research needs a structured authorisation record "
                       "(authorisations/<ref>.json); no authorisation reference is set"]
    if record.get("inline"):
        return False, ["external or destructive research needs a structured authorisation record at "
                       f"authorisations/{_REF_SAFE.sub('-', record.get('ref', 'REF'))}.json, "
                       "not just a free-text reference"]
    if record.get("_error"):
        return False, [f"authorisation record could not be read: {record['_error']}"]
    if not record.get("research_allowed"):
        errs.append("the authorisation record does not permit research mode (research_allowed=false)")
    if (destructive or dos) and not record.get("destructive_allowed"):
        errs.append("the authorisation record does not permit destructive/DoS testing "
                    "(destructive_allowed=false)")
    if _expired(record, today):
        errs.append(f"the authorisation expired on {record.get('expires')}")
    uncovered = _covers(record, in_scope or [])
    if uncovered:
        errs.append("these in-scope targets are not covered by the authorisation scope: "
                    + ", ".join(uncovered))
    return (not errs), errs
