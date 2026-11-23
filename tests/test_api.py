"""API-level checks: server rejects what the UI would block (curl-bypass case),
duplicates, hat gating, secret masking/round-trip and the reveal audit."""
import sqlite3
import unittest

import helpers
import migrations
import server

CRED = {"label": "admin", "login_url": "https://shop.acme-corp.co.uk/login", "username": "admin",
        "password": "Pa55!", "domain": "", "api_key": "", "otp_ref": "", "role": "admin", "notes": ""}


def cfg(**kw):
    base = {"hat": "white", "aggression": 2, "endpoints": [], "out_of_scope": [], "keysafe": []}
    base.update(kw)
    return base


class TestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = helpers.LiveServer()

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    _n = 0

    def create(self, c, code=200):
        TestApi._n += 1
        st, d = self.s.call("POST", "/api/projects", {"name": f"p{TestApi._n}", "config": c})
        self.assertEqual(st, code, d)
        return d

    def test_bad_formats_rejected_with_row_issues(self):
        d = self.create(cfg(endpoints=[{"type": "cidr", "data": "10.0.0.0/33"},
                                       {"type": "ip", "data": "banana"}]), 400)
        rows = [(i["list"], i["index"]) for i in d["issues"] if i["severity"] == "error"]
        self.assertEqual(rows, [("in_scope", 0), ("in_scope", 1)])

    def test_cross_list_duplicate_rejected(self):
        d = self.create(cfg(endpoints=[{"type": "hostname", "data": "a.example.com"}],
                            out_of_scope=[{"type": "hostname", "data": "A.EXAMPLE.COM"}]), 400)
        self.assertIn("In scope", d["error"])

    def test_private_rejected_for_external_position_only(self):
        ep = [{"type": "cidr", "data": "192.168.1.0/24"}]
        d = self.create(cfg(hat="grey", position="external", endpoints=ep), 400)
        self.assertIn("External test position", d["error"])
        self.create(cfg(hat="white", endpoints=ep))  # no position sent: White defaults to both
        got = self.create(cfg(hat="grey", position="internal", endpoints=ep))
        st, d = self.s.call("GET", f"/api/projects/{got['id']}")
        self.assertEqual((d["config"]["hat"], d["config"]["position"]), ("grey", "internal"))
        self.create(cfg(hat="black", position="internal", endpoints=ep))
        self.create(cfg(hat="grey", position="internal",
                        endpoints=[{"type": "ip", "data": "8.8.8.8"}]), 400)
        self.create(cfg(hat="grey", position="sideways", endpoints=ep), 400)

    def test_black_with_credential_rejected(self):
        d = self.create(cfg(hat="black", endpoints=[{"type": "hostname", "data": "shop.acme-corp.co.uk"}],
                            keysafe=[CRED]), 400)
        self.assertIn("Black hat", d["error"])

    def test_switch_to_black_does_not_delete_credentials(self):
        ep = [{"type": "hostname", "data": "shop.acme-corp.co.uk"}]
        pid = self.create(cfg(endpoints=ep, keysafe=[CRED]))["id"]
        st, _ = self.s.call("POST", f"/api/projects/{pid}", {"config": cfg(hat="black", endpoints=ep,
                                                                             keysafe=[CRED])})
        self.assertEqual(st, 400)
        st, d = self.s.call("GET", f"/api/projects/{pid}")
        self.assertEqual(d["config"]["hat"], "white")
        self.assertEqual(len(d["config"]["keysafe"]), 1)

    def test_secret_masking_roundtrip_and_audit(self):
        ep = [{"type": "hostname", "data": "shop.acme-corp.co.uk"}]
        pid = self.create(cfg(endpoints=ep, keysafe=[dict(CRED, api_key="KEY-1")]))["id"]
        st, d = self.s.call("GET", f"/api/projects/{pid}")
        k = d["config"]["keysafe"][0]
        self.assertEqual((k["password"], k["api_key"]), (server.SECRET_MASK, server.SECRET_MASK))
        self.assertTrue(k["id"])
        # save the masked copy back with a changed username: secrets must survive (matched by id)
        k["username"] = "admin2"
        st, _ = self.s.call("POST", f"/api/projects/{pid}", {"config": d["config"]})
        self.assertEqual(st, 200)
        con = sqlite3.connect(helpers.os.environ["PENENV_DB"])
        n0 = con.execute("SELECT COUNT(*) FROM key_access_audit").fetchone()[0]
        st, d = self.s.call("GET", f"/api/projects/{pid}?reveal=1")
        k = d["config"]["keysafe"][0]
        self.assertEqual((k["password"], k["api_key"], k["username"]), ("Pa55!", "KEY-1", "admin2"))
        rows = con.execute("SELECT entry_labels FROM key_access_audit").fetchall()
        self.assertEqual(len(rows), n0 + 1)
        self.assertNotIn("Pa55!", rows[-1][0])
        con.close()

    def test_new_project_cannot_contain_mask(self):
        self.create(cfg(keysafe=[dict(CRED, password=server.SECRET_MASK)]), 400)

    def test_validate_endpoint_dry_run(self):
        st, d = self.s.call("POST", "/api/projects/validate",
                            {"config": cfg(hat="grey", endpoints=[{"type": "url", "data": "http://10.0.0.5/"}])})
        self.assertEqual(st, 200)
        self.assertEqual(d["issues"][0]["severity"], "error")

    def test_unknown_project_is_404(self):
        st, _ = self.s.call("GET", "/api/projects/999999")
        self.assertEqual(st, 404)

    def test_switch_override_warning_and_roundtrip(self):
        c = cfg(aggression=0, switches={"bruteforce": "on", "sqlmap": "off", "dos": "on"},
                authorisation="", endpoints=[{"type": "ip", "data": "8.8.8.8"}])
        st, d = self.s.call("POST", "/api/projects/validate", {"config": c})
        self.assertEqual(st, 200, d)
        w = " | ".join(d["policy"]["warnings"])
        self.assertIn("Password brute force / credential stuffing' is switched on and overrides L0", w)
        self.assertIn("DoS / load testing' is switched on but stays off: needs the written authorisation", w)
        self.assertTrue(d["policy"]["switches"]["bruteforce"]["on"])
        self.assertEqual(d["policy"]["switches"]["dos"]["source"], "invariant")
        pid = self.create(c)["id"]
        st, got = self.s.call("GET", f"/api/projects/{pid}")
        sw = got["config"]["switches"]
        self.assertEqual((sw["bruteforce"], sw["sqlmap"], sw["dos"], sw["nmap"]), ("on", "off", "on", "auto"))
        self.assertEqual(got["config"]["schema"], migrations.CONFIG_VERSION)

    def test_policy_catalogue(self):
        st, d = self.s.call("GET", "/api/policy/catalogue")
        self.assertEqual(st, 200)
        self.assertEqual({x["id"] for x in d["switches"]}, set(server.policy.SWITCH_BY_ID))
        self.assertIn("research", {x["id"] for x in d["switches"]})

    def test_stack_roundtrips_and_is_cleaned(self):
        pid = self.create(cfg(endpoints=[{"type": "url", "data": "https://shop.acme-corp.co.uk"}],
                              stack=["openssh 8.1", "  ", "express 4.18"]))["id"]
        st, got = self.s.call("GET", f"/api/projects/{pid}")
        self.assertEqual(got["config"]["stack"], ["openssh 8.1", "express 4.18"])

    def test_dashboard_served(self):
        import urllib.request
        with urllib.request.urlopen(self.s.base + "/") as r:
            self.assertEqual(r.status, 200)



class TestAuthorisationApi(unittest.TestCase):
    """Dashboard Authorisations tab: create / validate / update / revoke over HTTP."""

    @classmethod
    def setUpClass(cls):
        cls.s = helpers.LiveServer()

    @classmethod
    def tearDownClass(cls):
        cls.s.stop()

    REC = {"ref": "API-ACME-01", "client": "Acme", "contract_ref": "SOW-9", "authorised_by": "J. Smith",
           "expires": "2099-01-31", "research_allowed": True, "destructive_allowed": False,
           "scope": [{"data": "https://shop.acme-corp.co.uk"}], "notes": "window Fri"}

    def test_lifecycle(self):
        st, d = self.s.call("POST", "/api/authorisations", self.REC)
        self.assertEqual(st, 200, d)
        aid = d["id"]
        self.assertEqual((d["state"], d["scope"][0]["type"]), ("active", "url"))
        st, d = self.s.call("POST", "/api/authorisations", self.REC)
        self.assertEqual(st, 409, d)
        st, d = self.s.call("POST", f"/api/authorisations/{aid}", {**self.REC, "expires": "2020-01-01"})
        self.assertEqual((st, d["state"]), (200, "expired"))
        st, d = self.s.call("GET", "/api/authorisations")
        self.assertIn("API-ACME-01", [r["ref"] for r in d["authorisations"]])
        st, d = self.s.call("POST", f"/api/authorisations/{aid}/revoke", {"reason": "test"})
        self.assertEqual((st, d["state"]), (200, "revoked"))
        st, d = self.s.call("POST", f"/api/authorisations/{aid}", self.REC)
        self.assertEqual(st, 400)
        st, d = self.s.call("GET", f"/api/authorisations/{aid}")
        self.assertEqual([a["action"] for a in d["audit"]], ["create", "update", "revoke"])

    def test_invalid_record_lists_every_problem(self):
        st, d = self.s.call("POST", "/api/authorisations", {"ref": "", "research_allowed": True})
        self.assertEqual(st, 400)
        self.assertGreaterEqual(len(d["problems"]), 4)

    def test_unknown_ids_are_404(self):
        for method, path in (("GET", "/api/authorisations/999999"), ("GET", "/api/authorisations/abc"),
                             ("POST", "/api/authorisations/999999/revoke")):
            st, _ = self.s.call(method, path, {} if method == "POST" else None)
            self.assertEqual(st, 404, path)

if __name__ == "__main__":
    unittest.main()
