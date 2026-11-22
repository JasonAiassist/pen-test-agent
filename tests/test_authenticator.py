"""T2.3/T2.4 — KeePassXC authenticator against a throwaway .kdbx (real keepassxc-cli)."""
import os
import sqlite3
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock

import helpers
import authenticator
import totp

SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # RFC 6238 SHA1 key
SEED2 = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
PW = "test-master-pw-123"
CRED = {"id": "abc123", "label": "tenant admin", "username": "admin@acme.test",
        "login_url": "https://shop.acme-corp.co.uk/login"}


def wait_for_fresh_window():
    if totp.remaining() < 3:  # avoid a code rolling over mid-assertion
        time.sleep(totp.remaining() + 0.2)


@unittest.skipUnless(authenticator.available(), "keepassxc-cli not installed")
class TestAuthenticator(unittest.TestCase):
    def setUp(self):
        self.kdbx = helpers.TMP / f"auth-{self.id().split('.')[-1]}.kdbx"
        os.environ["PENENV_KDBX"] = str(self.kdbx)

    def test_register_then_recover_matches_rfc6238(self):
        wait_for_fresh_window()
        res = authenticator.register("acme", CRED, SEED, PW)
        self.assertTrue(res["created_db"])
        self.assertEqual(oct(self.kdbx.stat().st_mode & 0o777), "0o600")
        self.assertEqual(res["otp_ref"], "penenv/acme/tenant admin [abc123]")
        wait_for_fresh_window()
        got = authenticator.code(res["otp_ref"], PW)["code"]
        self.assertEqual(got, totp.totp(totp.b32decode(SEED)))

    def test_wrong_password_is_401(self):
        authenticator.register("acme", CRED, SEED, PW)
        with self.assertRaises(authenticator.AuthError) as cm:
            authenticator.code("penenv/acme/tenant admin [abc123]", "wrong-password")
        self.assertEqual(cm.exception.code, 401)

    def test_reregister_replaces_seed_and_keeps_old_in_recycle_bin(self):
        authenticator.register("acme", CRED, SEED, PW)
        wait_for_fresh_window()
        ref = authenticator.register("acme", CRED, SEED2, PW)["otp_ref"]
        self.assertEqual(authenticator.code(ref, PW)["code"], totp.totp(totp.b32decode(SEED2)))
        ls = subprocess.run(["keepassxc-cli", "ls", "-R", "-q", str(self.kdbx)], input=PW + "\n",
                            capture_output=True, text=True).stdout
        self.assertIn("Recycle Bin", ls)

    def test_password_never_in_argv_and_no_plaintext_left(self):
        calls = []
        real = subprocess.run

        def spy(args, *a, **kw):
            calls.append((list(args), dict(kw.get("env") or {})))
            return real(args, *a, **kw)
        runtime = Path(os.environ.get("XDG_RUNTIME_DIR") or "/tmp")
        before = set(runtime.glob("penenv-otp-*"))
        with mock.patch.object(authenticator.subprocess, "run", spy):
            authenticator.register("acme", CRED, SEED, PW)
        self.assertTrue(calls)
        for args, env in calls:
            self.assertNotIn(PW, " ".join(args))
            self.assertNotIn(PW, " ".join(env.values()))
        self.assertEqual(set(runtime.glob("penenv-otp-*")), before)  # temp XML dir removed
        self.assertNotIn(SEED.encode(), self.kdbx.read_bytes())       # seed only inside the encrypted DB

    def test_bad_secret_rejected_before_db_created(self):
        with self.assertRaises(authenticator.AuthError) as cm:
            authenticator.register("acme", CRED, "not base32 !!", PW)
        self.assertEqual(cm.exception.code, 400)
        self.assertFalse(self.kdbx.exists())

    def test_missing_cli_is_503(self):
        with mock.patch.object(authenticator, "CLI", "definitely-not-keepassxc-cli"):
            with self.assertRaises(authenticator.AuthError) as cm:
                authenticator.code("x", PW)
        self.assertEqual(cm.exception.code, 503)


@unittest.skipUnless(authenticator.available(), "keepassxc-cli not installed")
class TestMfaApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = helpers.LiveServer()
        os.environ["PENENV_KDBX"] = str(helpers.TMP / "api-auth.kdbx")

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    def test_register_code_and_audit(self):
        cfg = {"hat": "grey", "endpoints": [{"type": "hostname", "data": "shop.acme-corp.co.uk"}],
               "keysafe": [dict(CRED, id="", password="pw")]}
        st, d = self.s.call("POST", "/api/projects", {"name": "mfa-proj", "config": cfg})
        self.assertEqual(st, 200, d)
        pid = d["id"]
        cid = self.s.call("GET", f"/api/projects/{pid}")[1]["config"]["keysafe"][0]["id"]
        wait_for_fresh_window()
        st, d = self.s.call("POST", f"/api/projects/{pid}/mfa/register",
                            {"cred_id": cid, "secret": SEED, "kdbx_password": PW})
        self.assertEqual(st, 200, d)
        st, p = self.s.call("GET", f"/api/projects/{pid}")
        self.assertEqual(p["config"]["keysafe"][0]["otp_ref"], d["otp_ref"])   # link persisted
        wait_for_fresh_window()
        st, c = self.s.call("POST", f"/api/projects/{pid}/mfa/code", {"cred_id": cid, "kdbx_password": PW})
        self.assertEqual((st, c["code"]), (200, totp.totp(totp.b32decode(SEED))))
        st, _ = self.s.call("POST", f"/api/projects/{pid}/mfa/code", {"cred_id": cid, "kdbx_password": "bad"})
        self.assertEqual(st, 401)
        con = sqlite3.connect(os.environ["PENENV_DB"])
        rows = con.execute("SELECT action, entry_labels FROM key_access_audit WHERE project_id=?"
                           " ORDER BY id", (pid,)).fetchall()
        raw = open(os.environ["PENENV_DB"], "rb").read()
        con.close()
        self.assertEqual([r[0] for r in rows], ["mfa_register", "mfa_code", "mfa_code_failed"])
        for _, labels in rows:
            self.assertNotIn(c["code"], labels)
        self.assertNotIn(SEED.encode(), raw)   # seed never stored in the tracker DB
        self.assertNotIn(PW.encode(), raw)     # nor the master password


if __name__ == "__main__":
    unittest.main()
