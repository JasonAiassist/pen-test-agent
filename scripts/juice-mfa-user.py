"""Create (or reuse) a Juice Shop test user with TOTP 2FA enabled, for the T2.5 MFA demo.

Prints JSON {email, password, seed}. The seed is written to the 0600 file given as argv[1]
(never printed), so it can be registered in a throwaway KeePassXC authenticator.
    python3 scripts/juice-mfa-user.py /tmp/penenv-smoke/seed [base_url]
"""
import base64
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tracker"))
import totp  # noqa: E402

seed_file = Path(sys.argv[1])
BASE = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:3000"
EMAIL = f"mfa-tester-{secrets.token_hex(3)}@penenv.test"
PASSWORD = "Pen-" + secrets.token_urlsafe(12)


def call(method, path, body=None, token=None):
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


st, d = call("POST", "/api/Users", {"email": EMAIL, "password": PASSWORD, "passwordRepeat": PASSWORD,
                                    "securityQuestion": {"id": 1}, "securityAnswer": "penenv"})
assert st in (200, 201), (st, d)
st, d = call("POST", "/rest/user/login", {"email": EMAIL, "password": PASSWORD})
assert st == 200, (st, d)
token = d["authentication"]["token"]
st, d = call("GET", "/rest/2fa/status", token=token)
assert st == 200 and not d.get("setup"), (st, d)
seed, setup_token = d["secret"], d["setupToken"]
code = totp.totp(totp.b32decode(seed))
st, d = call("POST", "/rest/2fa/setup", {"password": PASSWORD, "setupToken": setup_token, "initialToken": code}, token)
assert st == 200, (st, d)
# prove the login now demands a second factor
st, d = call("POST", "/rest/user/login", {"email": EMAIL, "password": PASSWORD})
assert st == 401 and d.get("status") == "totp_token_required", (st, d)
seed_file.parent.mkdir(parents=True, exist_ok=True)
fd = os.open(seed_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, seed.encode())
os.close(fd)
print(json.dumps({"email": EMAIL, "password": PASSWORD, "mfa": "enabled", "login_now_requires": "totp_token_required"}))
