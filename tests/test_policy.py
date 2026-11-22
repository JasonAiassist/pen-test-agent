"""T4.2 / T5.1: policy builder — every level x hat, precedence, invariants, network sets."""
import re
import unittest
from pathlib import Path

import helpers  # noqa: F401  (puts tracker/ on sys.path)
import policy

ROOT = Path(__file__).resolve().parents[1]
FAKE_DNS = {"app.example.com": ["93.184.216.34"], "juice-shop": ["172.20.0.2"],
            "admin.example.com": ["93.184.216.34"], "other.example.com": ["93.184.216.99"],
            "oast.pro": ["178.128.16.97"]}


def resolver(h):
    return FAKE_DNS.get(h, [])


def cfg(**kw):
    base = {"schema": 3, "hat": "white", "aggression": 2, "switches": {}, "authorisation": "",
            "endpoints": [{"type": "url", "data": "http://juice-shop:3000"}],
            "out_of_scope": [], "keysafe": [], "source_path": ""}
    base.update(kw)
    return base


PUBLIC = [{"type": "url", "data": "https://app.example.com/login"}]
CRED = [{"id": "c1", "label": "admin", "username": "a", "password": "p", "otp_ref": "penenv/x/admin"}]


class TestLevelsByHat(unittest.TestCase):
    def test_all_levels_and_hats(self):
        for level in range(6):
            for hat in policy.scope.HATS:
                with self.subTest(level=level, hat=hat):
                    p = policy.build_policy(cfg(aggression=level, hat=hat, endpoints=PUBLIC,
                                                keysafe=[] if hat == "black" else CRED), resolver)
                    self.assertEqual(p["errors"], [])
                    lv = policy.LEVELS[level]
                    self.assertEqual(p["strix"]["scan_mode"], lv["mode"])
                    self.assertEqual(p["strix"]["max_turns"], lv["max_turns"])
                    n = p["network"]
                    if level == 0:   # passive: zero target packets
                        self.assertEqual((n["allow_tcp"], n["contact"], n["conn_rate"]), ([], False, 0))
                    else:
                        self.assertIn(("93.184.216.34", "443"), n["allow_tcp"])
                        self.assertEqual(n["conn_rate"], lv["conn_rate"])
                    creds_tools = {"get_test_credential", "get_mfa_code"} & set(p["penenv_tools"])
                    self.assertEqual(bool(creds_tools), hat != "black")
                    # a tool is either usable or stubbed, never both
                    sw = p["switches"]
                    for s in policy.SWITCHES:
                        stubbed = set(s.get("paths", [])) <= set(p["deny_paths"]) and s.get("paths")
                        if s.get("paths"):
                            self.assertEqual(bool(stubbed), not sw[s["id"]]["on"], s["id"])

    def test_level_ladder_of_binaries(self):
        def allowed(level):
            return {k for k, v in policy.resolve_switches(cfg(aggression=level)).items()
                    if v["on"] and policy.SWITCH_BY_ID[k]["cls"].startswith("HARD-binary")}
        self.assertEqual(allowed(0), set())
        self.assertEqual(allowed(1), {"nmap", "httpx", "katana", "wafw00f", "browser", "curl_wget"})
        self.assertEqual(allowed(2) - allowed(1), {"ffuf", "dirsearch", "arjun", "nuclei", "sqlmap", "jwt_tool", "netcat"})
        self.assertEqual(allowed(3) - allowed(2), {"naabu"})
        self.assertEqual(allowed(5), allowed(3))


class TestPrecedence(unittest.TestCase):
    def test_switch_beats_level(self):
        p = policy.build_policy(cfg(aggression=1, switches={"sqlmap": "on", "curl_wget": "off"}), resolver)
        self.assertTrue(p["switches"]["sqlmap"]["on"])
        self.assertEqual(p["switches"]["sqlmap"]["source"], "switch")
        self.assertNotIn("/usr/bin/sqlmap", p["deny_paths"])
        self.assertIn("/usr/bin/curl", p["deny_paths"])
        self.assertTrue(any("overrides L1" in w for w in p["warnings"]))
        self.assertTrue(any("curl / wget" in w and "switched off" in w for w in p["warnings"]))

    def test_level_beats_hat(self):
        # Black hat does not restrict tools; the level does
        p = policy.build_policy(cfg(hat="black", aggression=3, endpoints=PUBLIC), resolver)
        self.assertTrue(p["switches"]["naabu"]["on"])

    def test_hat_beats_profile_defaults_for_creds(self):
        white = policy.resolve_switches(cfg(hat="white"))
        black = policy.resolve_switches(cfg(hat="black"))
        self.assertTrue(white["use_credentials"]["on"])
        self.assertFalse(black["use_credentials"]["on"])
        self.assertEqual(black["use_credentials"]["source"], "hat")

    def test_invariant_black_never_creds_even_if_switched_on(self):
        r = policy.resolve_switches(cfg(hat="black", switches={"use_credentials": "on", "use_mfa": "on"}))
        self.assertEqual((r["use_credentials"]["on"], r["use_credentials"]["source"]), (False, "invariant"))
        self.assertFalse(r["use_mfa"]["on"])

    def test_invariant_dos_needs_authorisation(self):
        r = policy.resolve_switches(cfg(aggression=5))
        self.assertFalse(r["dos"]["on"])
        self.assertFalse(r["destructive"]["on"])
        r = policy.resolve_switches(cfg(aggression=2, switches={"dos": "on"}, authorisation="SOW-2026-14 §3"))
        self.assertTrue(r["dos"]["on"])

    def test_dos_lifts_rate_cap(self):
        p = policy.build_policy(cfg(aggression=1, switches={"dos": "on"}, authorisation="ref"), resolver)
        self.assertEqual(p["network"]["conn_rate"], policy.LEVELS[5]["conn_rate"])

    def test_l0_with_tool_switched_on_opens_scope_with_warning(self):
        p = policy.build_policy(cfg(aggression=0, switches={"curl_wget": "on"}), resolver)
        self.assertTrue(p["network"]["contact"])
        self.assertEqual(p["network"]["conn_rate"], policy.LEVELS[1]["conn_rate"])
        self.assertTrue(any("no longer passive" in w for w in p["warnings"]))

    def test_function_tools(self):
        p = policy.build_policy(cfg(aggression=0), resolver)
        for t in ("web_search", "web_get_contents", "create_agent", "call_mcp", "repeat_request"):
            self.assertIn(t, p["disabled_tools"])
        p = policy.build_policy(cfg(aggression=2, switches={"web_search": "on"}), resolver)
        self.assertNotIn("web_search", p["disabled_tools"])
        self.assertNotIn("create_agent", p["disabled_tools"])
        self.assertEqual(p["strix"]["env"]["STRIX_TELEMETRY"], "0")

    def test_whitebox_only_with_source(self):
        self.assertFalse(policy.build_policy(cfg(hat="white"), resolver)["strix"]["whitebox"])
        self.assertTrue(policy.build_policy(cfg(hat="white", source_path="/src/app"), resolver)["strix"]["whitebox"])
        self.assertFalse(policy.build_policy(cfg(hat="grey", endpoints=PUBLIC, source_path="/src"), resolver)["strix"]["whitebox"])


class TestNetwork(unittest.TestCase):
    def test_scan_time_recheck_rejects_internal_for_external_position(self):
        p = policy.build_policy(cfg(hat="grey", position="external",
                                    endpoints=[{"type": "url", "data": "http://juice-shop:3000"}]), resolver)
        self.assertTrue(any("external test position" in e for e in p["errors"]))

    def test_grey_internal_scan_plan(self):
        # grey-box internal test: private target + provided login -> a runnable plan
        p = policy.build_policy(cfg(hat="grey", position="internal", aggression=1, keysafe=CRED), resolver)
        self.assertEqual(p["errors"], [])
        self.assertEqual(p["targets"], ["http://juice-shop:3000"])
        self.assertEqual(p["credentials"], ["admin"])
        self.assertFalse(p["strix"]["whitebox"])
        self.assertIn("TEST POSITION: internal", p["preamble"])

    def test_scan_time_recheck_rejects_public_for_internal_position(self):
        p = policy.build_policy(cfg(position="internal", endpoints=PUBLIC), resolver)
        self.assertTrue(any("internal test position" in e for e in p["errors"]))

    def test_missing_position_defaults_from_hat(self):
        self.assertEqual(policy.build_policy(cfg(hat="white"), resolver)["position"], "both")
        self.assertEqual(policy.build_policy(cfg(hat="grey", endpoints=PUBLIC), resolver)["position"], "external")

    def test_loopback_target_is_an_error(self):
        p = policy.build_policy(cfg(endpoints=[{"type": "url", "data": "http://127.0.0.1:3000"}]), resolver)
        self.assertTrue(any("loopback" in e for e in p["errors"]))

    def test_out_of_scope_ip_denied_and_wins_overlap(self):
        p = policy.build_policy(cfg(endpoints=[{"type": "cidr", "data": "172.20.0.0/24"}],
                                    out_of_scope=[{"type": "ip", "data": "172.20.0.3"}]), resolver)
        self.assertIn("172.20.0.3/32", p["network"]["deny"])
        self.assertTrue(any("out-of-scope wins" in w for w in p["warnings"]))

    def test_out_of_scope_hostname_resolved_and_denied(self):
        p = policy.build_policy(cfg(endpoints=PUBLIC, out_of_scope=[{"type": "hostname", "data": "other.example.com"}]), resolver)
        self.assertEqual(p["network"]["deny"], ["93.184.216.99/32"])

    def test_shared_ip_out_of_scope_is_soft_with_warning(self):
        p = policy.build_policy(cfg(endpoints=PUBLIC, out_of_scope=[{"type": "hostname", "data": "admin.example.com"}]), resolver)
        self.assertNotIn("93.184.216.34", p["network"]["deny"])
        self.assertIn("admin.example.com", p["soft_exclusions"])
        self.assertIn("admin.example.com", p["preamble"])
        self.assertTrue(any("cannot be separated" in w for w in p["warnings"]))

    def test_out_of_scope_path_is_soft(self):
        p = policy.build_policy(cfg(endpoints=PUBLIC, out_of_scope=[{"type": "url", "data": "https://app.example.com/admin"}]), resolver)
        self.assertIn("https://app.example.com/admin", p["soft_exclusions"])
        self.assertEqual(p["network"]["deny"], [])

    def test_hosts_pinned(self):
        p = policy.build_policy(cfg(), resolver)
        self.assertEqual(p["network"]["hosts"], {"juice-shop": ["172.20.0.2"]})
        self.assertEqual(p["network"]["allow_tcp"], [("172.20.0.2", "3000")])

    def test_oob_switch_opens_interactsh(self):
        p = policy.build_policy(cfg(switches={"oob_callbacks": "on"}), resolver)
        self.assertIn(("178.128.16.97", "443"), p["network"]["allow_tcp"])

    def test_render_nft_contains_sets_and_caps(self):
        p = policy.build_policy(cfg(aggression=1, out_of_scope=[{"type": "ip", "data": "172.20.0.3"}]), resolver)
        rules = policy.render_nft(p, "172.31.0.0/24")
        self.assertIn("172.20.0.2 . 3000", rules)
        self.assertIn("172.20.0.3/32", rules)
        self.assertIn(f"limit rate over {int(5 * 60 * 0.97)}/minute burst 5", rules)
        self.assertIn(f"limit rate over {256 * 1024} bytes/second", rules)
        self.assertLess(rules.index("out-of-scope"), rules.index("in-scope-tcp"))
        empty = policy.render_nft(policy.build_policy(cfg(aggression=0), resolver), "172.31.0.0/24")
        self.assertNotIn("elements", empty.split("set deny4")[0])


class TestDocsAgree(unittest.TestCase):
    def test_every_switch_documented_and_every_binary_inventoried(self):
        doc = (ROOT / "docs/enforcement-matrix.md").read_text()
        inv = (ROOT / "docs/sandbox-inventory.md").read_text()
        for s in policy.SWITCHES:
            self.assertIn(f"`{s['id']}`", doc, s["id"])
            for path in s.get("paths", []):
                name = Path(path).name
                self.assertTrue(path in inv or f"`{name}`" in inv or name == "nc.traditional", path)

    def test_documented_level_numbers_match(self):
        doc = (ROOT / "docs/enforcement-matrix.md").read_text()
        row = re.search(r"\| `--max-turns` per agent \|(.*)\|", doc).group(1)
        self.assertEqual([int(x) for x in re.findall(r"\d+", row)], [policy.LEVELS[i]["max_turns"] for i in range(6)])
        row = re.search(r"\| New connections / s \(HARD-net\) \|(.*)\|", doc).group(1)
        self.assertEqual([int(x) for x in re.findall(r"\d+", row)], [policy.LEVELS[i]["conn_rate"] for i in range(6)])


class TestSwitchMigration(unittest.TestCase):
    def test_legacy_and_partial(self):
        m = policy.migrate_switches({"se": True, "dos": False, "nmap": "off", "bogus": "on", "ffuf": "maybe"})
        self.assertEqual((m["social_engineering"], m["dos"], m["nmap"], m["ffuf"]), ("on", "off", "off", "auto"))
        self.assertNotIn("bogus", m)
        self.assertEqual(set(m), set(policy.SWITCH_BY_ID))


if __name__ == "__main__":
    unittest.main()
