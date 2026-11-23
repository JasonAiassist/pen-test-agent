"""T0.2 backup/idempotency/rollback and T1.3 legacy migration."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
import migrations

LEGACY = {
    "business": "demo", "endpoints": ["http://127.0.0.1:3000", "10.0.0.0/24", "8.8.8.8", "app.example.com",
                                      "example.com/admin"],
    "out_of_scope": ["score-board"], "level": "White hat (full knowledge)",
    "aggressiveness": "Level 3 — Aggressive",
    "keysafe": [{"label": "admin", "username": "a@b.c", "secret": "s3cret", "notes": "MFA on"}],
    "switches": {"dos": False},
}


def make_db(path: Path, cfg=LEGACY):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE projects(id INTEGER PRIMARY KEY, name TEXT, config TEXT,"
                " created_at TEXT, updated_at TEXT)")
    con.execute("INSERT INTO projects VALUES (1,'p',?, 't','t')", (json.dumps(cfg),))
    con.commit()
    con.close()


def read_cfg(path: Path) -> dict:
    con = sqlite3.connect(path)
    raw = con.execute("SELECT config FROM projects WHERE id=1").fetchone()[0]
    con.close()
    return json.loads(raw)


class TestMigration(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.db = self.dir / "t.db"
        make_db(self.db)

    def test_transform(self):
        c = migrations.migrate_config(LEGACY)
        self.assertEqual(c["endpoints"], [
            {"type": "url", "data": "http://127.0.0.1:3000"}, {"type": "cidr", "data": "10.0.0.0/24"},
            {"type": "ip", "data": "8.8.8.8"}, {"type": "hostname", "data": "app.example.com"},
            {"type": "", "data": "example.com/admin"}])  # ambiguous: kept + flagged, never dropped
        self.assertEqual(c["hat"], "white")
        self.assertEqual(c["aggression"], 3)
        self.assertNotIn("level", c)
        k = c["keysafe"][0]
        self.assertEqual((k["password"], k["username"], k["notes"]), ("s3cret", "a@b.c", "MFA on"))
        self.assertTrue(k["id"])
        self.assertNotIn("secret", k)
        # v3: legacy "dos: False" (= not permitted) becomes an explicit "off"; the rest are auto
        self.assertEqual(c["switches"]["dos"], "off")
        self.assertEqual({v for k, v in c["switches"].items() if k != "dos"}, {"auto"})
        self.assertEqual(c["authorisation"], "")
        self.assertEqual(c["position"], "both")  # white hat -> both
        self.assertEqual(c["stack"], [])  # v5: optional product stack, empty by default
        self.assertEqual(c["schema"], migrations.CONFIG_VERSION)

    def test_v3_to_v4_position_default_keeps_behaviour(self):
        v3 = dict(migrations.migrate_config(LEGACY), schema=3)
        for hat, want in (("white", "both"), ("grey", "external"), ("black", "external")):
            c = dict(v3, hat=hat)
            c.pop("position")
            got = migrations.migrate_config(c)
            self.assertEqual((got["position"], got["schema"]), (want, migrations.CONFIG_VERSION))
            self.assertEqual(got["switches"], v3["switches"])
            self.assertEqual(got["endpoints"], v3["endpoints"])
        explicit = dict(v3, hat="grey", position="internal")
        self.assertEqual(migrations.migrate_config(explicit)["position"], "internal")

    def test_v4_to_v5_adds_stack_default_empty(self):
        v4 = dict(migrations.migrate_config(LEGACY), schema=4)
        v4.pop("stack", None)
        got = migrations.migrate_config(v4)
        self.assertEqual((got["stack"], got["schema"]), ([], migrations.CONFIG_VERSION))
        # an explicit stack is preserved and cleaned of blanks
        explicit = dict(v4, stack=["openssh 8.1", "  ", "express 4.18"])
        explicit.pop("schema", None)
        explicit["schema"] = 4
        self.assertEqual(migrations.migrate_config(explicit)["stack"], ["openssh 8.1", "express 4.18"])

    def test_v2_to_v3_keeps_v2_data(self):
        v2 = migrations.migrate_config(LEGACY)
        v2 = dict(v2, schema=2, switches={"auto_exploit": True, "cvss": False})
        v2.pop("authorisation")
        c = migrations.migrate_config(v2)
        self.assertEqual((c["switches"]["autoexploit"], c["switches"]["cvss"]), ("on", "off"))
        self.assertEqual(c["endpoints"], v2["endpoints"])
        self.assertEqual(c["keysafe"], v2["keysafe"])

    def test_backup_created_before_change(self):
        before = self.db.read_bytes()
        rep = migrations.run(self.db)
        self.assertEqual(rep["migrated"], 1)
        backup = Path(rep["backup"])
        self.assertTrue(backup.is_file())
        con = sqlite3.connect(backup)
        self.assertEqual(json.loads(con.execute("SELECT config FROM projects").fetchone()[0]), LEGACY)
        con.close()
        self.assertEqual(oct(backup.stat().st_mode & 0o777), "0o600")
        self.assertNotEqual(before, self.db.read_bytes())

    def test_idempotent(self):
        migrations.run(self.db)
        first = read_cfg(self.db)
        rep = migrations.run(self.db)
        self.assertEqual(rep, {"migrated": 0, "backup": None})
        self.assertEqual(read_cfg(self.db), first)

    def test_rollback_restores_original(self):
        rep = migrations.run(self.db)
        migrations.restore(self.db, Path(rep["backup"]))
        self.assertEqual(read_cfg(self.db), LEGACY)


if __name__ == "__main__":
    unittest.main()
