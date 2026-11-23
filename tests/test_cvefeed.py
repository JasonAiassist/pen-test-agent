"""CVE knowledge feed: pure parsers, version maths, matcher, render + injected-HTTP sync.

Fully hermetic — no network. The HTTP layer is replaced with canned bytes, so this
exercises URL building, parsing, upsert, KEV/exploit flagging, matching and context
rendering end to end without touching the internet (mirroring how the real sandbox
never reaches it either).
"""
import json
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts tracker/ on sys.path)
import cvefeed


NVD = {
    "vulnerabilities": [
        {"cve": {
            "id": "CVE-2016-0777",
            "published": "2016-01-14T19:59:00.000",
            "lastModified": "2023-11-07T02:29:00.000",
            "descriptions": [{"lang": "en", "value": "The resend_bytes function in OpenSSH roaming."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 5.9, "baseSeverity": "MEDIUM",
                "vectorString": "CVSS:3.1/AV:N/AC:H"}}]},
            "weaknesses": [{"description": [{"value": "CWE-200"}]}],
            "references": [{"url": "https://example.test/a"}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 "versionStartIncluding": "5.4", "versionEndExcluding": "7.2"}]}]}],
        }},
        {"cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "Apache Log4j2 JNDI remote code execution (Log4Shell)."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
            "weaknesses": [{"description": [{"value": "CWE-502"}]}],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                 "versionEndExcluding": "2.15.0"}]}]}],
        }},
    ]
}

OSV = {"vulns": [{
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2022-24999"],
    "summary": "qs prototype pollution",
    "published": "2022-11-26T00:00:00Z",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
    "references": [{"url": "https://example.test/ghsa"}],
    "affected": [{"package": {"name": "qs", "ecosystem": "npm"},
                  "ranges": [{"type": "SEMVER", "events": [{"introduced": "6.0.0"}, {"fixed": "6.10.3"}]}]}],
}]}

KEV = {"vulnerabilities": [
    {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j2",
     "vulnerabilityName": "Log4Shell", "dueDate": "2021-12-24"}]}

EXPLOITDB_CSV = (
    "id,file,description,date,author,type,platform,port,codes\n"
    "50592,exploits/x.py,\"Apache Log4j RCE\",2021-12-12,someone,remote,java,0,CVE-2021-44228;OSVDB-1\n")


def mem_db():
    return cvefeed.connect(Path(tempfile.mkdtemp()) / "cve.db")


class TestParsers(unittest.TestCase):
    def test_parse_nvd(self):
        recs = {r["id"]: r for r in cvefeed.parse_nvd(NVD)}
        ssh = recs["CVE-2016-0777"]
        self.assertEqual(ssh["cvss"], 5.9)
        self.assertEqual(ssh["severity"], "MEDIUM")
        self.assertEqual(ssh["cwe"], "CWE-200")
        self.assertEqual(ssh["products"][0]["product"], "openssh")
        self.assertEqual(ssh["products"][0]["ranges"][0],
                         {"introduced": "5.4", "fixed": "7.2"})
        self.assertEqual(recs["CVE-2021-44228"]["severity"], "CRITICAL")

    def test_parse_nvd_accepts_bytes(self):
        recs = cvefeed.parse_nvd(json.dumps(NVD).encode())
        self.assertEqual(len(recs), 2)

    def test_parse_osv_maps_ghsa_to_cve(self):
        rec = cvefeed.parse_osv(OSV)[0]
        self.assertEqual(rec["id"], "CVE-2022-24999")
        self.assertEqual(rec["source"], "ghsa")
        self.assertIn("GHSA-xxxx-yyyy-zzzz", rec["aliases"])
        self.assertEqual(rec["severity"], "HIGH")
        self.assertEqual(rec["products"][0]["product"], "qs")
        self.assertEqual(rec["products"][0]["ranges"][0], {"introduced": "6.0.0", "fixed": "6.10.3"})

    def test_parse_kev_and_exploitdb(self):
        self.assertIn("CVE-2021-44228", cvefeed.parse_kev(KEV))
        edb = cvefeed.parse_exploitdb(EXPLOITDB_CSV)
        self.assertEqual(edb["CVE-2021-44228"][0]["edb_id"], "50592")


class TestVersionRange(unittest.TestCase):
    def test_in_range(self):
        self.assertTrue(cvefeed._in_range("7.1", "5.4", "7.2"))
        self.assertFalse(cvefeed._in_range("7.2", "5.4", "7.2"))   # fixed is exclusive
        self.assertFalse(cvefeed._in_range("5.3", "5.4", "7.2"))
        self.assertTrue(cvefeed._in_range(None, "5.4", "7.2"))     # unknown version cannot be excluded
        self.assertTrue(cvefeed._in_range("2.14.0", None, "2.15.0"))
        self.assertTrue(cvefeed._in_range("1.2.10", "1.2.9", None))  # 1.2.10 > 1.2.9


class TestMatch(unittest.TestCase):
    def setUp(self):
        self.con = mem_db()
        cvefeed.upsert(self.con, cvefeed.parse_nvd(NVD))
        cvefeed.upsert(self.con, cvefeed.parse_osv(OSV))

    def test_version_in_range_matches(self):
        hits = {r["id"] for r in cvefeed.match_stack(self.con, ["openssh 7.1"])}
        self.assertIn("CVE-2016-0777", hits)

    def test_version_out_of_range_excluded(self):
        hits = {r["id"] for r in cvefeed.match_stack(self.con, ["openssh 8.1"])}
        self.assertNotIn("CVE-2016-0777", hits)

    def test_product_without_version_matches_all(self):
        hits = {r["id"] for r in cvefeed.match_stack(self.con, ["openssh"])}
        self.assertIn("CVE-2016-0777", hits)

    def test_npm_package_matches(self):
        hits = {r["id"] for r in cvefeed.match_stack(self.con, ["qs 6.5.0"])}
        self.assertIn("CVE-2022-24999", hits)

    def test_kev_sorts_first(self):
        cvefeed.apply_kev(self.con, cvefeed.parse_kev(KEV))
        rows = cvefeed.match_stack(self.con, ["log4j", "openssh 7.1"])
        self.assertEqual(rows[0]["id"], "CVE-2021-44228")
        self.assertTrue(rows[0]["kev"])

    def test_no_terms_no_match(self):
        self.assertEqual(cvefeed.match_stack(self.con, []), [])


class TestUpsertFlags(unittest.TestCase):
    def test_kev_flag_survives_reupsert(self):
        con = mem_db()
        cvefeed.upsert(con, cvefeed.parse_nvd(NVD))
        cvefeed.apply_kev(con, cvefeed.parse_kev(KEV))
        cvefeed.upsert(con, cvefeed.parse_nvd(NVD))  # a later NVD refresh must not clear KEV
        row = con.execute("SELECT kev, exploited FROM cve WHERE id='CVE-2021-44228'").fetchone()
        self.assertEqual((row["kev"], row["exploited"]), (1, 1))

    def test_exploitdb_sets_exploited_and_ref(self):
        con = mem_db()
        cvefeed.upsert(con, cvefeed.parse_nvd(NVD))
        cvefeed.apply_exploitdb(con, cvefeed.parse_exploitdb(EXPLOITDB_CSV))
        row = cvefeed._row_to_dict(
            con.execute("SELECT * FROM cve WHERE id='CVE-2021-44228'").fetchone())
        self.assertTrue(row["exploited"])
        self.assertTrue(any("exploit-db.com/exploits/50592" in r for r in row["refs"]))


class TestRenderAndContext(unittest.TestCase):
    def test_render_marks_known_exploited(self):
        con = mem_db()
        cvefeed.upsert(con, cvefeed.parse_nvd(NVD))
        cvefeed.apply_kev(con, cvefeed.parse_kev(KEV))
        block = cvefeed.render_scan_context(cvefeed.match_stack(con, ["log4j"]))
        self.assertIn("CVE-2021-44228", block)
        self.assertIn("KNOWN-EXPLOITED", block)
        self.assertIn("Do NOT fetch vulnerability data from the network", block)

    def test_render_empty_when_no_matches(self):
        self.assertEqual(cvefeed.render_scan_context([]), "")

    def test_context_for_project(self):
        db = Path(tempfile.mkdtemp()) / "cve.db"
        con = cvefeed.connect(db)
        cvefeed.upsert(con, cvefeed.parse_nvd(NVD))
        con.close()
        cfg = {"stack": ["log4j 2.14.0"]}
        block = cvefeed.context_for_project(cfg, enabled=True, db_path=db)
        self.assertIn("CVE-2021-44228", block)
        # disabled, no stack, or missing DB -> empty, never raising
        self.assertEqual(cvefeed.context_for_project(cfg, enabled=False, db_path=db), "")
        self.assertEqual(cvefeed.context_for_project({"stack": []}, db_path=db), "")
        self.assertEqual(cvefeed.context_for_project(cfg, db_path=db.parent / "absent.db"), "")


class TestSyncWithFakeHTTP(unittest.TestCase):
    def test_sync_sources_end_to_end(self):
        con = mem_db()

        def fake_http(url, *a, **kw):
            if "services.nvd.nist.gov" in url:
                self.assertIn("resultsPerPage", url)
                return json.dumps(NVD).encode()
            if "api.osv.dev" in url:
                return json.dumps(OSV).encode()
            if "cisa.gov" in url:
                return json.dumps(KEV).encode()
            if "gitlab.com" in url:
                return EXPLOITDB_CSV.encode()
            raise AssertionError(f"unexpected host: {url}")

        cvefeed.sync_nvd(con, http=fake_http, since_days=7)
        cvefeed.sync_osv(con, http=fake_http, package="qs", ecosystem="npm")
        cvefeed.sync_kev(con, http=fake_http)
        cvefeed.sync_exploitdb(con, http=fake_http)

        st = cvefeed.status(con)
        self.assertGreaterEqual(st["total"], 3)
        self.assertEqual(st["kev"], 1)
        self.assertIn("nvd", st["feeds"])
        row = con.execute("SELECT kev, exploited FROM cve WHERE id='CVE-2021-44228'").fetchone()
        self.assertEqual((row["kev"], row["exploited"]), (1, 1))

    def test_nvd_url_incremental_params(self):
        url = cvefeed.nvd_url(since_days=3, keyword="openssh")
        self.assertIn("lastModStartDate", url)
        self.assertIn("keywordSearch=openssh", url)


if __name__ == "__main__":
    unittest.main()
