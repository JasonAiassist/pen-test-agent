"""T2.5 / T5.3: scan-time credential + MFA channel (per-scan token, audited, revoked) and scan events."""
import os
import sqlite3
import unittest

import helpers
import authenticator
import server
import totp

SEED = "JBSWY3DPEHPK3PXP"
PW = "scan-channel-test-pw"
CRED = {"label": "admin", "login_url": "https://shop.acme-corp.co.uk/login", "username": "admin@acme",
        "password": "Pa55!", "domain": "", "api_key": "k-1", "otp_ref": "", "role": "admin", "notes": ""}


def cfg(**kw):
    base = {"hat": "grey", "aggression": 2, "keysafe": [dict(CRED)], "out_of_scope": [],
            "endpoints": [{"type": "url", "data": "https://shop.acme-corp.co.uk/login"}]}
    base.update(kw)
    return base


class TestScanChannel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = helpers.LiveServer()

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    _n = 0

    def project(self, c):
        TestScanChannel._n += 1
        st, d = self.s.call("POST", "/api/projects", {"name": f"sc{TestScanChannel._n}", "config": c})
        self.assertEqual(st, 200, d)
        return d["id"]

    def token(self, pid):
        st, d = self.s.call("POST", f"/api/projects/{pid}/scan-token", {"run_label": "t", "policy_summary": {"level": 2}})
        self.assertEqual(st, 200, d)
        return d["token"], d["scan_id"]

    def audit(self, pid):
        con = sqlite3.connect(os.environ["PENENV_DB"])
        rows = con.execute("SELECT action, entry_labels FROM key_access_audit WHERE project_id=?", (pid,)).fetchall()
        con.close()
        return rows

    def test_credential_by_label_audited_then_token_rejected_after_revoke(self):
        pid = self.project(cfg())
        tok, _ = self.token(pid)
        st, d = self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "admin"})
        self.assertEqual((st, d["username"], d["password"]), (200, "admin@acme", "Pa55!"))
        rows = self.audit(pid)
        self.assertIn("scan_credential", [r[0] for r in rows])
        self.assertTrue(all("Pa55!" not in (r[1] or "") for r in rows))
        self.assertEqual(self.s.call("POST", "/api/scan-channel/revoke", {"token": tok})[0], 200)
        st, d = self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "admin"})
        self.assertEqual(st, 401)
        self.assertIn("scan has ended", d["error"])

    def test_bad_token_and_unknown_label(self):
        pid = self.project(cfg())
        self.assertEqual(self.s.call("POST", "/api/scan-channel/credential", {"token": "nope", "label": "admin"})[0], 401)
        tok, _ = self.token(pid)
        self.assertEqual(self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "root"})[0], 404)
        self.assertIn("scan_credential_unknown", [r[0] for r in self.audit(pid)])

    def test_switch_off_blocks_channel(self):
        pid = self.project(cfg(switches={"use_credentials": "off"}))
        tok, _ = self.token(pid)
        st, d = self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "admin"})
        self.assertEqual(st, 403)

    def test_expired_token(self):
        pid = self.project(cfg())
        tok, sid = self.token(pid)
        con = sqlite3.connect(os.environ["PENENV_DB"])
        con.execute("UPDATE scan_tokens SET expires_at=0 WHERE id=?", (sid,))
        con.commit()
        con.close()
        self.assertEqual(self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "admin"})[0], 401)

    def test_events_shown_in_project_scans(self):
        pid = self.project(cfg())
        tok, sid = self.token(pid)
        ev = {"kind": "policy_denied", "detail": "/usr/bin/sqlmap -u http://x", "at": "2026-11-22T13:00:00Z"}
        self.assertEqual(self.s.call("POST", "/api/scan-channel/events", {"token": tok, "events": [ev]})[0], 200)
        st, d = self.s.call("GET", f"/api/projects/{pid}/scans")
        scan = next(x for x in d["scans"] if x["scan_id"] == sid)
        self.assertEqual(scan["events"], [ev])
        self.assertEqual(scan["policy"], {"level": 2})

    @unittest.skipUnless(authenticator.available(), "keepassxc-cli not installed")
    def test_otp_through_channel_matches_rfc6238(self):
        os.environ["PENENV_KDBX"] = str(helpers.TMP / "scan-channel.kdbx")
        pid = self.project(cfg())
        st, d = self.s.call("GET", f"/api/projects/{pid}")
        cred_id = d["config"]["keysafe"][0]["id"]
        st, d = self.s.call("POST", f"/api/projects/{pid}/mfa/register",
                            {"cred_id": cred_id, "secret": SEED, "kdbx_password": PW})
        self.assertEqual(st, 200, d)
        tok, _ = self.token(pid)
        st, d = self.s.call("POST", "/api/scan-channel/otp", {"token": tok, "label": "admin", "kdbx_password": PW})
        self.assertEqual(st, 200, d)
        self.assertIn(d["code"], {totp.totp(totp.b32decode(SEED), at=__import__("time").time() + dt) for dt in (-30, 0, 30)})
        self.assertIn("scan_otp", [r[0] for r in self.audit(pid)])
        self.s.call("POST", "/api/scan-channel/revoke", {"token": tok})
        self.assertEqual(self.s.call("POST", "/api/scan-channel/otp",
                                     {"token": tok, "label": "admin", "kdbx_password": PW})[0], 401)

    def test_black_hat_channel_refused(self):
        pid = self.project(cfg(hat="black", keysafe=[]))
        tok, _ = self.token(pid)
        self.assertEqual(self.s.call("POST", "/api/scan-channel/credential", {"token": tok, "label": "admin"})[0], 403)


if __name__ == "__main__":
    unittest.main()
