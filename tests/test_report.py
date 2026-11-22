"""Report generator (tracker/report.py): markdown subset, model building, HTML rendering,
and (optionally, when the toolchain is present and PENENV_SLOW_TESTS=1) PDF/DOCX conversion.

Uses the committed completed run strix_runs/juice-shop-3000_af55 as a fixture.
"""
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts tracker/ on sys.path)
import report

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "strix_runs" / "juice-shop-3000_af55"


class TestMarkdown(unittest.TestCase):
    def test_fenced_code_is_escaped_and_wrapped(self):
        out = report.md_to_html("before\n```python\nx = 1 < 2 and '<b>'\n```\nafter")
        self.assertIn("<pre><code>", out)
        self.assertIn("&lt;b&gt;", out)          # html escaped
        self.assertNotIn("```", out)             # fence consumed
        self.assertIn("<p>before</p>", out)

    def test_inline_code_bold_and_lists(self):
        out = report.md_to_html("Use `curl` and **stop**.\n- one\n- two\n\n1. a\n2. b")
        self.assertIn("<code>curl</code>", out)
        self.assertIn("<strong>stop</strong>", out)
        self.assertIn("<ul>", out)
        self.assertIn("<ol>", out)
        self.assertEqual(out.count("<li>"), 4)

    def test_no_raw_markup_leaks_and_escapes_html(self):
        out = report.md_to_html("a **b** `c` <script>alert(1)</script>")
        self.assertNotIn("**", out)
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_code_block_honours_existing_fence(self):
        once = report._code_block("```js\nvar a=1;\n```")
        self.assertEqual(once.count("<pre><code>"), 1)
        verb = report._code_block("plain no fence < >")
        self.assertIn("<pre><code>", verb)
        self.assertIn("&lt; &gt;", verb)
        self.assertEqual(report._code_block(""), "")


class TestModel(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = report.load_findings(FIXTURE)
        cls.model = report.build_model(FIXTURE, project={"name": "demo",
                     "endpoints": [{"type": "url", "data": "http://juice-shop:3000"}],
                     "hat": "white", "position": "internal", "aggression": 4}, title=None)

    def test_findings_loaded_and_sorted(self):
        self.assertEqual(len(self.findings), 10)
        ranks = [report.SEV_RANK[f["severity"]] for f in self.findings]
        self.assertEqual(ranks, sorted(ranks))                      # severity ascending rank
        self.assertTrue(all(f["severity"] in report.SEV_RANK for f in self.findings))

    def test_cvss_parsed_numeric(self):
        top = self.findings[0]
        self.assertIsInstance(top["_cvss"], float)
        self.assertEqual(top["severity"], "CRITICAL")

    def test_counts_and_total(self):
        self.assertEqual(self.model["total"], 10)
        self.assertEqual(self.model["counts"]["CRITICAL"], 2)
        self.assertEqual(self.model["counts"]["HIGH"], 1)
        self.assertEqual(self.model["counts"]["MEDIUM"], 7)

    def test_by_type_grouping_covers_all(self):
        grouped = sum(len(v) for v in self.model["by_type"].values())
        self.assertEqual(grouped, 10)
        self.assertTrue(any(k.startswith("CWE-") for k in self.model["by_type"]))

    def test_top_risks_are_highest_severity(self):
        self.assertTrue(self.model["top"])
        self.assertTrue(all(f["severity"] in ("CRITICAL", "HIGH") for f in self.model["top"][:3]))


class TestRenderHTML(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        model = report.build_model(FIXTURE, project={"name": "demo",
                 "endpoints": [{"type": "url", "data": "http://juice-shop:3000"}],
                 "hat": "white", "position": "internal", "aggression": 4}, title=None)
        cls.html = report.render_html(model)

    def test_no_unfilled_tokens(self):
        self.assertEqual(re.findall(r"\{\{[A-Z_]+\}\}", self.html), [])

    def test_has_all_major_sections(self):
        body = self.html.split("</head>", 1)[1]
        for needle in ['class="cover"', "Contents", "Executive Summary", "Top risks",
                       "Detailed Findings", "Appendix A", "Appendix B", "Severity model"]:
            self.assertIn(needle, body, needle)

    def test_one_card_per_finding_with_remediation_and_code(self):
        self.assertEqual(len(re.findall(r'<div class="finding" id="', self.html)), 10)
        self.assertEqual(self.html.count("Proposed correction"), 10)
        self.assertEqual(self.html.count("Proof-of-concept code"), 10)

    def test_no_markdown_leaks_in_body(self):
        body = self.html.split("</head>", 1)[1]
        self.assertEqual(body.count("```"), 0)
        self.assertEqual(len(re.findall(r"\*\*", body)), 0)

    def test_docx_variant_is_word_safe_and_not_duplicated(self):
        model = report.build_model(FIXTURE, project={"name": "demo",
                 "endpoints": [{"type": "url", "data": "http://juice-shop:3000"}],
                 "hat": "white", "position": "internal", "aggression": 4}, title=None)
        d = report.render_docx_html(model)
        self.assertEqual(re.findall(r"\{\{[A-Z_]+\}\}", d), [])          # tokens filled
        self.assertEqual(len(re.findall(r"<h3>\[[CHMLI]\d+\]", d)), 10)  # one heading per finding, no dup
        self.assertEqual(d.count("Proposed correction"), 10)
        self.assertNotIn("display:flex", d)                              # Word-safe: no flex/grid/gradient
        self.assertNotIn("display:grid", d)
        self.assertNotIn("linear-gradient", d)
        self.assertEqual(d.count("<section"), 0)                         # page-break sections stripped

    def test_empty_run_renders_no_findings_notice(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "empty_run"
            d.mkdir()
            (d / "run.json").write_text('{"run_id":"empty_run","status":"completed",'
                                        '"targets_info":[{"original":"http://x:1"}]}')
            (d / "vulnerabilities.json").write_text("[]")
            html = report.render_html(report.build_model(d, project=None, title=None))
            self.assertIn("No vulnerabilities were confirmed", html)
            self.assertEqual(re.findall(r"\{\{[A-Z_]+\}\}", html), [])


@unittest.skipUnless(os.environ.get("PENENV_SLOW_TESTS") == "1",
                     "set PENENV_SLOW_TESTS=1 to exercise Chromium/LibreOffice conversion")
class TestConversion(unittest.TestCase):
    def test_pdf_and_docx(self):
        with tempfile.TemporaryDirectory() as td:
            out = report.generate(FIXTURE, Path(td), ["html", "pdf", "docx"],
                                  project={"name": "demo"}, title=None)
            self.assertTrue(Path(out["html"]).stat().st_size > 1000)
            if shutil.which("chromium") or shutil.which("chromium-browser"):
                self.assertTrue(Path(out["pdf"]).stat().st_size > 1000)
            if shutil.which("soffice") or shutil.which("libreoffice"):
                self.assertTrue(Path(out["docx"]).stat().st_size > 1000)


if __name__ == "__main__":
    unittest.main()
