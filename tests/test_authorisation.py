"""Research-mode authorisation gate: fail-closed loading + decision, and the
build_policy integration that refuses research when the contract does not cover it."""
import datetime as _dt
import json
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts tracker/ on sys.path)
import authorisation
import policy

TODAY = _dt.date(2026, 6, 1)
INTERNAL = [{"type": "url", "data": "http://juice-shop:3000"}]
PUBLIC = [{"type": "url", "data": "https://app.example.com/login"}]
FAKE_DNS = {"app.example.com": ["93.184.216.34"], "juice-shop": ["172.20.0.2"]}


def resolver(h):
    return FAKE_DNS.get(h, [])


def write_record(d: Path, ref: str, **over) -> None:
    rec = {"ref": ref, "client": "ACME", "contract_ref": "SOW-1", "authorised_by": "CISO",
           "expires": "2099-12-31", "research_allowed": True, "destructive_allowed": False,
           "scope": ["https://app.example.com/login"], "notes": ""}
    rec.update(over)
    (d / f"{ref}.json").write_text(json.dumps(rec))


class TestLoad(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def test_none_when_no_ref(self):
        self.assertIsNone(authorisation.load_record({}, auth_dir=self.d))

    def test_inline_when_ref_has_no_file(self):
        rec = authorisation.load_record({"authorisation": "SOW-2026-14 §3"}, auth_dir=self.d)
        self.assertTrue(rec["inline"])

    def test_structured_when_file_present(self):
        write_record(self.d, "ACME-2026")
        rec = authorisation.load_record({"authorisation": "ACME-2026"}, auth_dir=self.d)
        self.assertFalse(rec.get("inline"))
        self.assertTrue(rec["research_allowed"])
        self.assertEqual(rec["scope"][0]["data"], "https://app.example.com/login")

    def test_no_path_traversal(self):
        self.assertIsNone(authorisation.record_path("../../etc/passwd", auth_dir=self.d))


class TestDecision(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())

    def auth(self, **kw):
        kw.setdefault("today", TODAY)
        return authorisation.authorise_research(**kw)

    def test_internal_lab_needs_only_self_auth(self):
        inline = authorisation.load_record({"authorisation": "lab"}, auth_dir=self.d)
        ok, why = self.auth(record=inline, position="internal", destructive=False, dos=False,
                            in_scope=INTERNAL)
        self.assertTrue(ok, why)

    def test_internal_lab_without_any_ref_refused(self):
        ok, why = self.auth(record=None, position="internal", destructive=False, dos=False,
                            in_scope=INTERNAL)
        self.assertFalse(ok)
        self.assertTrue(any("self-authorisation" in w for w in why))

    def test_external_with_inline_only_refused(self):
        inline = authorisation.load_record({"authorisation": "SOW-x"}, auth_dir=self.d)
        ok, why = self.auth(record=inline, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("structured authorisation record" in w for w in why))

    def test_external_with_valid_record_ok(self):
        write_record(self.d, "ACME")
        rec = authorisation.load_record({"authorisation": "ACME"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertTrue(ok, why)

    def test_research_flag_false_refused(self):
        write_record(self.d, "NoRes", research_allowed=False)
        rec = authorisation.load_record({"authorisation": "NoRes"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("does not permit research" in w for w in why))

    def test_destructive_requires_flag(self):
        write_record(self.d, "ACME")  # destructive_allowed defaults False
        rec = authorisation.load_record({"authorisation": "ACME"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="internal", destructive=True, dos=False,
                            in_scope=INTERNAL)
        self.assertFalse(ok)
        self.assertTrue(any("destructive" in w for w in why))

    def test_expired_refused(self):
        write_record(self.d, "Old", expires="2026-01-01")
        rec = authorisation.load_record({"authorisation": "Old"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("expired" in w for w in why))

    def test_scope_not_covered_refused(self):
        write_record(self.d, "ACME", scope=["https://other.example.com"])
        rec = authorisation.load_record({"authorisation": "ACME"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("not covered" in w for w in why))

    def test_cidr_scope_covers_member_ip(self):
        write_record(self.d, "Net", scope=[{"type": "cidr", "data": "10.0.0.0/24"}],
                     destructive_allowed=True)
        rec = authorisation.load_record({"authorisation": "Net"}, auth_dir=self.d)
        ok, why = self.auth(record=rec, position="internal", destructive=True, dos=False,
                            in_scope=[{"type": "ip", "data": "10.0.0.9"}])
        self.assertTrue(ok, why)


class TestBuildPolicyIntegration(unittest.TestCase):
    """build_policy consults the real AUTH_DIR; point it at a temp dir for the test."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self._orig = authorisation.AUTH_DIR
        authorisation.AUTH_DIR = self.d

    def tearDown(self):
        authorisation.AUTH_DIR = self._orig

    def cfg(self, **kw):
        base = {"schema": 5, "hat": "grey", "aggression": 2, "switches": {"research": "on"},
                "authorisation": "", "endpoints": INTERNAL, "out_of_scope": [], "keysafe": [],
                "source_path": "", "position": "internal"}
        base.update(kw)
        return base

    def test_internal_self_auth_enables_research(self):
        p = policy.build_policy(self.cfg(authorisation="lab-self"), resolver)
        self.assertTrue(p["research"])
        self.assertTrue(p["switches"]["research"]["on"])
        self.assertIn("RESEARCH MODE (authorised)", p["preamble"])

    def test_research_without_any_authorisation_is_refused(self):
        # needs_auth already forces it off; research stays off and the switch is not "on"
        p = policy.build_policy(self.cfg(authorisation=""), resolver)
        self.assertFalse(p["research"])
        self.assertFalse(p["switches"]["research"]["on"])

    def test_external_research_needs_structured_record(self):
        p = policy.build_policy(self.cfg(position="external", endpoints=PUBLIC,
                                         authorisation="inline-only"), resolver)
        self.assertFalse(p["research"])
        self.assertTrue(any("research mode refused" in e for e in p["errors"]))

    def test_external_research_with_record_enabled(self):
        write_record(self.d, "ACME")
        p = policy.build_policy(self.cfg(position="external", endpoints=PUBLIC,
                                         authorisation="ACME"), resolver)
        self.assertTrue(p["research"], p["errors"])
        self.assertEqual(p["authorisation_ref"], "ACME")


if __name__ == "__main__":
    unittest.main()
