"""Research-mode authorisation gate: DB-backed records (create / update / revoke / audit),
fail-closed loading + decision, and the build_policy integration that refuses research
when the contract does not cover it. Hermetic: throwaway SQLite databases only."""
import datetime as _dt
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts tracker/ on sys.path, points PENENV_DB at a temp DB)
import authorisation
import policy

TODAY = _dt.date(2026, 6, 1)
INTERNAL = [{"type": "url", "data": "http://juice-shop:3000"}]
PUBLIC = [{"type": "url", "data": "https://app.example.com/login"}]
FAKE_DNS = {"app.example.com": ["93.184.216.34"], "juice-shop": ["172.20.0.2"]}


def resolver(h):
    return FAKE_DNS.get(h, [])


def new_con() -> sqlite3.Connection:
    return sqlite3.connect(Path(tempfile.mkdtemp()) / "auth.db")


def write_record(con, ref: str, **over) -> dict:
    rec = {"ref": ref, "client": "ACME", "contract_ref": "SOW-1", "authorised_by": "CISO",
           "expires": "2099-12-31", "research_allowed": True, "destructive_allowed": False,
           "scope": ["https://app.example.com/login"], "notes": ""}
    rec.update(over)
    saved, errs = authorisation.save_record(con, rec)
    assert not errs, errs
    return saved


class TestStore(unittest.TestCase):
    def setUp(self):
        self.con = new_con()

    def load(self, ref):
        return authorisation.load_record({"authorisation": ref}, con=self.con)

    def test_none_when_no_ref(self):
        self.assertIsNone(authorisation.load_record({}, con=self.con))

    def test_inline_when_no_record_has_the_ref(self):
        rec = self.load("SOW-2026-14 §3")
        self.assertTrue(rec["inline"])

    def test_structured_when_record_present(self):
        write_record(self.con, "ACME-2026")
        rec = self.load("@ACME-2026")  # a leading @ is tolerated
        self.assertFalse(rec.get("inline"))
        self.assertTrue(rec["research_allowed"])
        self.assertEqual(rec["scope"][0], {"type": "url", "data": "https://app.example.com/login"})

    def test_validation_rejects_incomplete_records(self):
        _, errs = authorisation.save_record(self.con, {"ref": "x y", "research_allowed": True,
                                                       "scope": ["not a target!"]})
        joined = " | ".join(errs)
        for needle in ("reference must be", "client is required", "authorised by",
                       "expiry date is required", "contract / SOW", "scope entry 1"):
            self.assertIn(needle, joined)
        _, errs = authorisation.save_record(self.con, {"ref": "A", "client": "c", "authorised_by": "b",
                                                       "expires": "31/12/2099"})
        self.assertTrue(any("YYYY-MM-DD" in e for e in errs))
        self.assertEqual(authorisation.list_records(self.con), [])

    def test_duplicate_ref_rejected(self):
        write_record(self.con, "DUP")
        _, errs = authorisation.save_record(self.con, {"ref": "DUP", "client": "c", "authorised_by": "b"})
        self.assertTrue(any("already exists" in e for e in errs))

    def test_update_and_audit_trail(self):
        rec = write_record(self.con, "UPD")
        upd, errs = authorisation.save_record(self.con, {**rec, "destructive_allowed": True}, rec["id"])
        self.assertFalse(errs)
        self.assertTrue(upd["destructive_allowed"])
        self.assertEqual([a["action"] for a in authorisation.audit_trail(self.con, rec["id"])],
                         ["create", "update"])

    def test_revoked_record_refuses_even_lab_research(self):
        rec = write_record(self.con, "REV")
        authorisation.revoke_record(self.con, rec["id"], "contract terminated")
        loaded = self.load("REV")
        self.assertIn("revoked", loaded["_error"])
        ok, why = authorisation.authorise_research(loaded, position="internal", destructive=False,
                                                   dos=False, in_scope=INTERNAL, today=TODAY)
        self.assertFalse(ok)
        self.assertIn("revoked", why[0])
        _, errs = authorisation.save_record(self.con, {**rec, "notes": "x"}, rec["id"])
        self.assertTrue(any("revoked" in e for e in errs))
        self.assertEqual([a["action"] for a in authorisation.audit_trail(self.con, rec["id"])],
                         ["create", "revoke"])

    def test_unreadable_database_fails_closed(self):
        bad = Path(tempfile.mkdtemp()) / "not-a-db"
        bad.write_bytes(b"this is not sqlite" * 100)
        old = os.environ.get("PENENV_DB")
        os.environ["PENENV_DB"] = str(bad)
        try:
            rec = authorisation.load_record({"authorisation": "ANY"})
        finally:
            os.environ["PENENV_DB"] = old
        self.assertIn("_error", rec)
        ok, _ = authorisation.authorise_research(rec, position="internal", destructive=False,
                                                 dos=False, in_scope=INTERNAL, today=TODAY)
        self.assertFalse(ok)


class TestDecision(unittest.TestCase):
    def setUp(self):
        self.con = new_con()

    def auth(self, **kw):
        kw.setdefault("today", TODAY)
        return authorisation.authorise_research(**kw)

    def test_internal_lab_needs_only_self_auth(self):
        inline = authorisation.load_record({"authorisation": "lab"}, con=self.con)
        ok, why = self.auth(record=inline, position="internal", destructive=False, dos=False,
                            in_scope=INTERNAL)
        self.assertTrue(ok, why)

    def test_internal_lab_without_any_ref_refused(self):
        ok, why = self.auth(record=None, position="internal", destructive=False, dos=False,
                            in_scope=INTERNAL)
        self.assertFalse(ok)
        self.assertTrue(any("self-authorisation" in w for w in why))

    def test_external_with_inline_only_refused(self):
        inline = authorisation.load_record({"authorisation": "SOW-x"}, con=self.con)
        ok, why = self.auth(record=inline, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("structured authorisation record" in w for w in why))

    def test_external_with_valid_record_ok(self):
        write_record(self.con, "ACME")
        rec = authorisation.load_record({"authorisation": "ACME"}, con=self.con)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertTrue(ok, why)

    def test_research_flag_false_refused(self):
        write_record(self.con, "NoRes", research_allowed=False)
        rec = authorisation.load_record({"authorisation": "NoRes"}, con=self.con)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("does not permit research" in w for w in why))

    def test_destructive_requires_flag(self):
        write_record(self.con, "ACME")  # destructive_allowed defaults False
        rec = authorisation.load_record({"authorisation": "ACME"}, con=self.con)
        ok, why = self.auth(record=rec, position="internal", destructive=True, dos=False,
                            in_scope=INTERNAL)
        self.assertFalse(ok)
        self.assertTrue(any("destructive" in w for w in why))

    def test_expired_refused(self):
        write_record(self.con, "Old", expires="2026-01-01")
        rec = authorisation.load_record({"authorisation": "Old"}, con=self.con)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("expired" in w for w in why))

    def test_scope_not_covered_refused(self):
        write_record(self.con, "ACME", scope=["https://other.example.com"])
        rec = authorisation.load_record({"authorisation": "ACME"}, con=self.con)
        ok, why = self.auth(record=rec, position="external", destructive=False, dos=False,
                            in_scope=PUBLIC)
        self.assertFalse(ok)
        self.assertTrue(any("not covered" in w for w in why))

    def test_cidr_scope_covers_member_ip(self):
        write_record(self.con, "Net", scope=[{"type": "cidr", "data": "10.0.0.0/24"}],
                     destructive_allowed=True)
        rec = authorisation.load_record({"authorisation": "Net"}, con=self.con)
        ok, why = self.auth(record=rec, position="internal", destructive=True, dos=False,
                            in_scope=[{"type": "ip", "data": "10.0.0.9"}])
        self.assertTrue(ok, why)


class TestBuildPolicyIntegration(unittest.TestCase):
    """build_policy reads the tracker DB ($PENENV_DB, a temp file under helpers)."""

    def setUp(self):
        self.con = sqlite3.connect(authorisation.default_db_path())

    def tearDown(self):
        self.con.close()

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
        write_record(self.con, "POLICY-ACME")
        p = policy.build_policy(self.cfg(position="external", endpoints=PUBLIC,
                                         authorisation="POLICY-ACME"), resolver)
        self.assertTrue(p["research"], p["errors"])
        self.assertEqual(p["authorisation_ref"], "POLICY-ACME")

    def test_revoking_the_record_switches_research_off(self):
        rec = write_record(self.con, "POLICY-REV")
        authorisation.revoke_record(self.con, rec["id"])
        p = policy.build_policy(self.cfg(position="external", endpoints=PUBLIC,
                                         authorisation="POLICY-REV"), resolver)
        self.assertFalse(p["research"])
        self.assertTrue(any("revoked" in e for e in p["errors"]))


if __name__ == "__main__":
    unittest.main()
