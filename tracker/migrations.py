"""Backup-first, idempotent schema migrations for the tracker DB (T0.2).

Project config versions:
  v1  endpoints/out_of_scope = [str]; level/aggressiveness = display labels;
      keysafe = [{label, username, secret, notes}]
  v2  endpoints/out_of_scope = [{type, data}]; hat = white|grey|black;
      aggression = 0..5; keysafe = [{id, label, login_url, username, password,
      domain, api_key, otp_ref, role, notes}]
  v3  switches = {id: auto|on|off} over policy.SWITCHES (legacy booleans: True->on,
      False->off, since the old box meant "permitted"); authorisation = written
      authorisation reference (required for DoS/destructive)
  v4  position = external|internal|both (test position, independent of the hat).
      Default keeps v3 behaviour: White -> both; Grey/Black -> external (they were
      internet-facing only before v4)

Rules: a backup is written before any row changes; legacy values that cannot
be typed are kept with type "" (the UI and validator flag them) - never dropped.
"""
from __future__ import annotations

import json
import secrets
import shutil
import sqlite3
import time
from pathlib import Path

import policy
import scope

CONFIG_VERSION = 4

HAT_FROM_LABEL = {"black": "black", "grey": "grey", "gray": "grey", "white": "white"}


def _hat(label: str | None) -> str:
    low = (label or "").lower()
    for k, v in HAT_FROM_LABEL.items():
        if low.startswith(k):
            return v
    return "grey"


def _aggr(label) -> int:
    if isinstance(label, int) and 0 <= label <= 5:
        return label
    low = str(label or "").lower()
    if low.startswith("passive"):
        return 0
    for n in range(1, 6):
        if f"level {n}" in low:
            return n
    return 2


def _typed(items) -> list[dict]:
    out = []
    for v in items or []:
        if isinstance(v, dict):
            out.append({"type": v.get("type", ""), "data": str(v.get("data", ""))})
            continue
        s = str(v).strip()
        if s:
            out.append({"type": scope.infer_type(s) or "", "data": s})
    return out


def new_cred_id() -> str:
    return secrets.token_hex(6)


def migrate_config(cfg: dict) -> dict:
    """Pure v1→v2→v3→v4 transform. Idempotent: a current config is returned unchanged."""
    if cfg.get("schema") == CONFIG_VERSION:
        return cfg
    out = dict(cfg)
    if out.get("schema") not in (2, 3):
        out = _v1_to_v2(out)
    if out.get("schema") == 2:
        out = dict(out)
        out["switches"] = policy.migrate_switches(out.get("switches"))
        out.setdefault("authorisation", "")
        out["schema"] = 3
    out = dict(out)
    if out.get("position") not in scope.POSITIONS:
        out["position"] = scope.default_position(out.get("hat"))
    out["schema"] = CONFIG_VERSION
    return out


def _v1_to_v2(cfg: dict) -> dict:
    out = dict(cfg)
    out["endpoints"] = _typed(cfg.get("endpoints"))
    out["out_of_scope"] = _typed(cfg.get("out_of_scope"))
    out["hat"] = cfg.get("hat") if cfg.get("hat") in scope.HATS else _hat(cfg.get("level"))
    out["aggression"] = _aggr(cfg.get("aggression", cfg.get("aggressiveness")))
    out.pop("level", None)
    out.pop("aggressiveness", None)
    creds = []
    for e in cfg.get("keysafe") or []:
        if not isinstance(e, dict):
            continue
        c = {k: "" for k in scope.CRED_FIELDS}
        c.update({k: e[k] for k in scope.CRED_FIELDS if k in e and e[k] is not None})
        if "secret" in e and not c["password"]:
            c["password"] = e["secret"]
        c["id"] = c["id"] or new_cred_id()
        creds.append(c)
    out["keysafe"] = creds
    out.setdefault("source_path", "")
    out["schema"] = 2
    return out


def backup_db(db_path: Path, tag: str) -> Path:
    dest_dir = db_path.parent / "backups"
    dest_dir.mkdir(mode=0o700, exist_ok=True)
    dest = dest_dir / f"{db_path.stem}.{tag}.{time.strftime('%Y%m%d-%H%M%S')}.db"
    src = sqlite3.connect(db_path)
    dst = sqlite3.connect(dest)
    with dst:
        src.backup(dst)  # consistent online copy, safe while the server runs
    src.close()
    dst.close()
    dest.chmod(0o600)
    return dest


def pending_projects(con: sqlite3.Connection) -> list[tuple[int, dict]]:
    rows = con.execute("SELECT id, config FROM projects").fetchall()
    out = []
    for pid, raw in rows:
        cfg = json.loads(raw)
        if cfg.get("schema") != CONFIG_VERSION:
            out.append((pid, cfg))
    return out


def run(db_path: Path) -> dict:
    """Migrate every project row to CONFIG_VERSION. Returns a small report."""
    con = sqlite3.connect(db_path, timeout=30)
    try:
        has_projects = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='projects'").fetchone()
        todo = pending_projects(con) if has_projects else []
        if not todo:
            return {"migrated": 0, "backup": None}
        con.close()
        backup = backup_db(db_path, f"pre-config-v{CONFIG_VERSION}")
        con = sqlite3.connect(db_path, timeout=30)
        with con:
            for pid, cfg in todo:
                con.execute("UPDATE projects SET config=? WHERE id=?",
                            (json.dumps(migrate_config(cfg), ensure_ascii=False), pid))
        return {"migrated": len(todo), "backup": str(backup)}
    finally:
        con.close()


def restore(db_path: Path, backup: Path) -> None:
    shutil.copy2(backup, db_path)
