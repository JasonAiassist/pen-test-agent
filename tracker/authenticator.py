"""KeePassXC as the MFA authenticator (Point 2, decision Q2).

KeePassXC holds the TOTP seeds; the tracker DB stores only a reference
(otp_ref = KeePassXC entry path). Operations:
  register(...)  enrol a site's MFA setup secret into the authenticator .kdbx
  code(...)      recover the current one-time code from KeePassXC

Security properties (verified by tests/test_authenticator.py):
  - master password goes to keepassxc-cli on stdin, never argv/env/disk/logs
  - the seed exists on disk only inside the encrypted .kdbx; the transient
    import XML lives in a 0700 dir on RAM-backed $XDG_RUNTIME_DIR and is
    unlinked in a finally block
  - re-registering moves the old entry to KeePassXC's recycle bin (recoverable)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

import totp

CLI = os.environ.get("PENENV_KEEPASSXC_CLI", "keepassxc-cli")
GROUP = "penenv"


class AuthError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def kdbx_path() -> Path:
    p = os.environ.get("PENENV_KDBX")
    if p:
        return Path(p)
    base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    return base / "penenv" / "authenticator.kdbx"


def available() -> bool:
    return shutil.which(CLI) is not None


def _require_cli() -> None:
    if not available():
        raise AuthError(503, "keepassxc-cli is not installed — install KeePassXC to use MFA")


def _run(args: list[str], password: str, extra_stdin: str = "", timeout: int = 30) -> subprocess.CompletedProcess:
    # Commands that open the DB run without -q: under -q keepassxc-cli suppresses the
    # "Invalid credentials" error, making a wrong password indistinguishable from a
    # missing entry. Its password prompt goes to stderr, so stdout stays clean.
    stdin = password + "\n" + extra_stdin
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR")}
    env["QT_QPA_PLATFORM"] = "offscreen"
    p = subprocess.run([CLI, *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=env)
    err = (p.stderr or "") + (p.stdout or "")
    if p.returncode != 0 and re.search(r"Invalid credentials were provided|wrong key|HMAC mismatch", err, re.I):
        raise AuthError(401, "KeePassXC authenticator: wrong master password")
    return p


def _safe(s: str) -> str:
    s = re.sub(r"[/\\\x00-\x1f]+", "-", s or "").strip(" .-")
    return s[:60] or "unnamed"


def entry_path(project: str, cred: dict) -> str:
    label = _safe(cred.get("label") or cred.get("username") or "login")
    return f"{GROUP}/{_safe(project)}/{label} [{cred['id']}]"


def _private_tmpdir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    d = Path(tempfile.mkdtemp(prefix="penenv-otp-", dir=base if base and os.path.isdir(base) else None))
    d.chmod(0o700)
    return d


def ensure_db(password: str) -> bool:
    """Create the authenticator DB on first use. Returns True if created."""
    db = kdbx_path()
    if db.exists():
        return False
    if len(password) < 8:
        raise AuthError(400, "new authenticator database: choose a master password of 8+ characters")
    db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = _run(["db-create", "-q", "-p", str(db)], password, password + "\n")
    if p.returncode != 0 or not db.exists():
        raise AuthError(500, "could not create the KeePassXC authenticator database")
    db.chmod(0o600)
    return True


def register(project: str, cred: dict, setup_secret: str, password: str) -> dict:
    _require_cli()
    try:
        params = totp.parse_setup(setup_secret)
    except totp.OtpError as e:
        raise AuthError(400, str(e)) from None
    created = ensure_db(password)
    db = kdbx_path()
    path = entry_path(project, cred)
    group_names = path.split("/")[:-1]
    title = path.split("/")[-1]
    uri = totp.to_uri(params, f"{params['issuer'] or 'penenv'}:{cred.get('username') or title}")
    # verify the password before touching anything (also proves the DB opens)
    probe = _run(["ls", str(db)], password)
    if probe.returncode != 0:
        raise AuthError(500, "KeePassXC authenticator could not be opened")
    # move a previous registration to the recycle bin (recoverable), then add the new one
    _run(["rm", str(db), path], password)
    tmp = _private_tmpdir()
    try:
        xml = tmp / "entry.xml"
        stage = tmp / "stage.kdbx"
        groups_open = "".join(f"<Group><Name>{escape(g)}</Name>" for g in group_names)
        groups_close = "</Group>" * len(group_names)
        fd = os.open(xml, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write('<?xml version="1.0" encoding="utf-8" standalone="yes"?><KeePassFile><Meta>'
                    "<Generator>penenv</Generator></Meta><Root><Group><Name>Root</Name>"
                    f"{groups_open}<Entry>"
                    f"<String><Key>Title</Key><Value>{escape(title)}</Value></String>"
                    f"<String><Key>UserName</Key><Value>{escape(cred.get('username') or '')}</Value></String>"
                    f"<String><Key>URL</Key><Value>{escape(cred.get('login_url') or '')}</Value></String>"
                    f'<String><Key>otp</Key><Value ProtectInMemory="True">{escape(uri)}</Value></String>'
                    f"<String><Key>Notes</Key><Value>penenv project {escape(project)}; registered "
                    f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}</Value></String>"
                    f"</Entry>{groups_close}</Group></Root></KeePassFile>")
        p = _run(["import", "-q", "-p", str(xml), str(stage)], password, password + "\n")
        if p.returncode != 0:
            raise AuthError(500, "KeePassXC import of the MFA entry failed")
        p = _run(["merge", "-s", str(db), str(stage)], password)
        if p.returncode != 0:
            raise AuthError(500, "KeePassXC merge of the MFA entry failed")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    got = code(path, password)
    expect = totp.totp(params["key"], period=params["period"], digits=params["digits"], algo=params["algo"])
    if got["code"] != expect and totp.remaining(params["period"]) > 1:
        raise AuthError(500, "KeePassXC produced a different code than expected — registration not trusted")
    return {"otp_ref": path, "code": got["code"], "remaining": got["remaining"], "created_db": created}


def code(path: str, password: str) -> dict:
    _require_cli()
    db = kdbx_path()
    if not db.exists():
        raise AuthError(404, "no KeePassXC authenticator database yet — register MFA first")
    p = _run(["show", "-t", str(db), path], password)
    out = (p.stdout or "").strip().splitlines()
    if p.returncode != 0 or not out or not re.fullmatch(r"\d{6,8}", out[-1].strip()):
        raise AuthError(404, f"no MFA entry {path!r} in the authenticator")
    return {"code": out[-1].strip(), "remaining": totp.remaining()}
