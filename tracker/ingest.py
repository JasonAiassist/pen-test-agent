#!/usr/bin/env python3
"""Ingest Strix run outputs into the penenv vulnerability tracker.

Scans ROOT/strix_runs/<run>/ for run.json + vulnerabilities.json, upserts
findings into ROOT/tracker/penenv.db, and maintains the lifecycle:
open -> (seen again) -> fixed (absent from a later run of the same target)
-> reopened (seen again). Manual statuses accepted / false_positive are
preserved across re-detection and can be reset from the dashboard.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "strix_runs"
DB_PATH = Path(os.environ["PENENV_DB"]) if os.environ.get("PENENV_DB") else ROOT / "tracker" / "penenv.db"

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MANUAL_STATUSES = {"accepted", "false_positive"}
EVIDENCE_FIELDS = ("description", "impact", "poc_description", "technical_analysis")


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS runs(
            dir TEXT PRIMARY KEY,
            name TEXT, targets TEXT, mode TEXT,
            started TEXT, finished TEXT, status TEXT,
            findings_count INTEGER, report_path TEXT,
            ingested_at TEXT
        );
        CREATE TABLE IF NOT EXISTS findings(
            id TEXT PRIMARY KEY,
            target TEXT, endpoint TEXT, method TEXT, title TEXT,
            severity TEXT, status TEXT,
            first_run TEXT, last_run TEXT,
            first_seen TEXT, last_seen TEXT,
            times_seen INTEGER DEFAULT 0,
            fixed_in_run TEXT, note TEXT
        );
        CREATE TABLE IF NOT EXISTS occurrences(
            finding_id TEXT, run_dir TEXT,
            severity TEXT, title TEXT, evidence TEXT,
            PRIMARY KEY(finding_id, run_dir)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
        CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
        """
    )
    return con


def norm_target(t: str) -> str:
    t = (t or "").strip().lower()
    t = re.sub(r"^https?://", "", t)
    return t.rstrip("/")


def title_bucket(title: str) -> str:
    words = re.findall(r"[a-z0-9]+", (title or "").lower())
    return " ".join(words[:8])


def finding_identity(target_norm: str, endpoint: str, method: str, title: str) -> str:
    bucket = title_bucket(title)
    ep = (endpoint or "").strip().lower()
    ep = re.sub(r"https?://", "", ep)
    # strip obvious per-run volatile parts (ids, uuids, long numbers)
    ep = re.sub(r"/[0-9a-f]{8,}|\b\d{2,}\b", "", ep)
    me = (method or "").strip().upper()
    base = f"{target_norm}|{ep or bucket}|{me}|{bucket}"
    return hashlib.sha1(base.encode()).hexdigest()[:16]


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def discover_runs() -> list[Path]:
    if not RUNS_DIR.exists():
        return []
    out = []
    for d in sorted(RUNS_DIR.iterdir()):
        if d.is_dir() and (d / "run.json").exists():
            out.append(d)
    return out


def parse_run(d: Path) -> dict | None:
    run = load_json(d / "run.json", None)
    if not isinstance(run, dict):
        return None
    vulns = load_json(d / "vulnerabilities.json", [])
    if not isinstance(vulns, list):
        vulns = []
    targets = run.get("targets") or run.get("target") or []
    if isinstance(targets, str):
        targets = [targets]
    # Strix >=1.4 writes targets_info: [{type, details:{target_url}, original}]
    for ti in run.get("targets_info") or []:
        if isinstance(ti, dict):
            det = ti.get("details") or {}
            t = ti.get("original") or det.get("target_url")
            if isinstance(t, str) and t:
                targets.append(t)
    report = d / "penetration_test_report.md"
    return {
        "dir": d.name,
        "path": str(d),
        "name": run.get("run_name") or run.get("name") or d.name,
        "targets": [norm_target(t) for t in targets if isinstance(t, str)],
        "mode": run.get("mode") or run.get("run_mode") or "default",
        "started": run.get("start_time") or run.get("started") or "",
        "finished": run.get("end_time") or run.get("finished") or "",
        "status": run.get("status") or "",
        "report_path": str(report) if report.exists() else "",
        "vulns": [v for v in vulns if isinstance(v, dict)],
    }


def evidence_json(v: dict) -> str:
    return json.dumps({k: v.get(k, "") for k in EVIDENCE_FIELDS}, ensure_ascii=False)


def ingest(verbose: bool = True) -> dict:
    con = connect()
    summary = {"runs_ingested": 0, "runs_skipped": 0, "new": 0, "updated": 0,
               "fixed": 0, "reopened": 0}
    # target -> set of finding ids seen in the most recent ingested run
    latest_seen: dict[str, tuple[str, set[str]]] = {}
    for d in discover_runs():
        data = parse_run(d)
        if data is None:
            continue
        already = con.execute("SELECT 1 FROM runs WHERE dir=?", (d.name,)).fetchone()
        if already:
            summary["runs_skipped"] += 1
            continue
        con.execute(
            "INSERT INTO runs(dir,name,targets,mode,started,finished,status,"
            "findings_count,report_path,ingested_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (d.name, data["name"], ",".join(data["targets"]), data["mode"],
             data["started"], data["finished"], data["status"],
             len(data["vulns"]), data["report_path"], ts()),
        )
        summary["runs_ingested"] += 1
        if not data["targets"]:
            continue
        ids_this_run: dict[str, set[str]] = {t: set() for t in data["targets"]}
        for v in data["vulns"]:
            for target in data["targets"]:
                title = str(v.get("title") or v.get("name") or "unknown finding")
                endpoint = str(v.get("endpoint") or v.get("url") or "")
                method = str(v.get("method") or "")
                sev = str(v.get("severity") or "INFO").upper()
                sev = sev if sev in SEV_ORDER else "INFO"
                fid = finding_identity(target, endpoint, method, title)
                ids_this_run[target].add(fid)
                row = con.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
                if row is None:
                    con.execute(
                        "INSERT INTO findings(id,target,endpoint,method,title,severity,"
                        "status,first_run,last_run,first_seen,last_seen,times_seen) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,1)",
                        (fid, target, endpoint, method, title, sev, "open",
                         d.name, d.name, ts(), ts()),
                    )
                    summary["new"] += 1
                else:
                    prev = row["severity"]
                    new_sev = sev if SEV_ORDER.get(sev, 0) >= SEV_ORDER.get(prev, 0) else prev
                    status = row["status"]
                    reopened = False
                    if status == "fixed":
                        status, reopened = "open", True
                        summary["reopened"] += 1
                    # manual statuses survive re-detection
                    if status in MANUAL_STATUSES:
                        pass
                    con.execute(
                        "UPDATE findings SET last_run=?, last_seen=?, times_seen=?, "
                        "severity=?, status=?, fixed_in_run=NULL WHERE id=?",
                        (d.name, ts(), row["times_seen"] + 1, new_sev, status, fid),
                    )
                    summary["updated"] += 1 if not reopened else 0
                con.execute(
                    "INSERT OR REPLACE INTO occurrences(finding_id,run_dir,severity,"
                    "title,evidence) VALUES(?,?,?,?,?)",
                    (fid, d.name, sev, title, evidence_json(v)),
                )
        for target, ids in ids_this_run.items():
            prev = latest_seen.get(target)
            if prev is None:
                latest_seen[target] = (d.name, ids)
            else:
                # runs sort by dir name (timestamped); later wins
                if d.name > prev[0]:
                    latest_seen[target] = (d.name, ids)
    # fixed: findings for target not present in that target's latest run
    for target, (run_name, ids) in latest_seen.items():
        for row in con.execute(
            "SELECT id,status FROM findings WHERE target=? AND status='open'", (target,)
        ).fetchall():
            if row["id"] not in ids:
                con.execute(
                    "UPDATE findings SET status='fixed', fixed_in_run=? WHERE id=?",
                    (run_name, row["id"]),
                )
                summary["fixed"] += 1
    con.commit()
    con.close()
    if verbose:
        print(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    ingest()
