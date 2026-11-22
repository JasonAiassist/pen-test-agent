"""T1.1 validator, T1.2 duplicates, T3.1 internet-facing, T3.2 hat rules (pure)."""
import unittest

import helpers  # noqa: F401  (sets PENENV_DB / sys.path)
import scope
from helpers import fake_resolver

VALID = {
    "ip": ["8.8.8.8", "203.0.113.7", "10.0.0.1", "0.0.0.0", "255.255.255.255", "::1",
           "2001:4860:4860::8888", "fe80::1", "::ffff:8.8.8.8"],
    "cidr": ["203.0.113.0/24", "10.0.0.0/8", "8.8.8.8/32", "0.0.0.0/0", "10.0.0.5/24",
             "2001:db8::/32", "::/0", "192.168.1.0/30"],
    "hostname": ["example.com", "app.example.com", "a-b.example.co.uk", "localhost", "intranet",
                 "xn--bcher-kva.example", "example.com.", "a1.b2.c3.d4.example", "123abc.example.com"],
    "url": ["https://example.com", "http://example.com/", "https://app.example.com:8443/api/v1",
            "http://10.0.0.5:3000", "https://[2001:db8::1]/x", "https://example.com/path?q=1",
            "HTTPS://EXAMPLE.COM", "http://127.0.0.1:3000"],
}
INVALID = {
    "ip": ["256.1.1.1", "1.2.3", "10.0.0.0/24", "banana", "", " 8.8.8.8", "1.2.3.4.5", "::gg",
           "example.com"],
    "cidr": ["10.0.0.0/33", "10.0.0.0", "300.0.0.0/8", "banana/8", "10.0.0.0/-1", "2001:db8::/129",
             "", "10.0.0.0 /8"],
    "hostname": ["-bad-.com", "bad-.com", "banana split", "a..b", "https://example.com",
                 "example.com/path", "8.8.8.8", "1.2.3", "x" * 64 + ".com", "", "under_score.com"],
    "url": ["ftp://x.example.com", "example.com", "https://", "http://user:pw@example.com",
            "https://exa mple.com", "https://-bad-.com", "https://example.com:99999", "banana",
            "javascript:alert(1)"],
}


class TestValidator(unittest.TestCase):
    def test_valid(self):
        for t, vals in VALID.items():
            for v in vals:
                with self.subTest(type=t, value=v):
                    self.assertIsNone(scope.validate_endpoint(t, v))

    def test_invalid(self):
        for t, vals in INVALID.items():
            for v in vals:
                with self.subTest(type=t, value=v):
                    self.assertIsNotNone(scope.validate_endpoint(t, v))

    def test_counts_meet_dod(self):
        for t in scope.TYPES:
            self.assertGreaterEqual(len(VALID[t]), 8)
            self.assertGreaterEqual(len(INVALID[t]), 8)

    def test_unknown_type(self):
        self.assertIn("unknown type", scope.validate_endpoint("email", "a@b.c"))


def E(t, d):
    return {"type": t, "data": d}


class TestDuplicates(unittest.TestCase):
    def errs(self, ins, outs=()):
        return [i for i in scope.check_endpoints(list(ins), list(outs)) if i["severity"] == "error"]

    def test_in_list_duplicate(self):
        e = self.errs([E("hostname", "a.example.com"), E("hostname", "A.Example.com.")])
        self.assertEqual(len(e), 1)
        self.assertIn("duplicate of row 1", e[0]["message"])

    def test_cross_list_duplicate_names_both(self):
        e = self.errs([E("ip", "203.0.113.5")], [E("ip", "203.0.113.5")])
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0]["list"], "out_of_scope")
        self.assertIn("In scope", e[0]["message"])

    def test_url_variants_are_duplicates(self):
        e = self.errs([E("url", "https://Example.com/app/"), E("url", "https://example.com:443/app")])
        self.assertEqual(len(e), 1)

    def test_scheme_difference_is_not_duplicate(self):
        self.assertEqual(self.errs([E("url", "http://example.com"), E("url", "https://example.com")]), [])

    def test_ip_equals_slash32(self):
        self.assertEqual(len(self.errs([E("ip", "10.0.0.5")], [E("cidr", "10.0.0.5/32")])), 1)

    def test_ipv6_canonical(self):
        self.assertEqual(len(self.errs([E("ip", "2001:db8:0:0::1"), E("ip", "2001:DB8::1")])), 1)

    def test_overlap_is_warning_not_error(self):
        issues = scope.check_endpoints([E("cidr", "10.0.0.0/24")], [E("ip", "10.0.0.1")])
        self.assertEqual([i for i in issues if i["severity"] == "error"], [])
        self.assertTrue(any("excluded from in-scope range" in i["message"] for i in issues))

    def test_invalid_entries_reported_with_index(self):
        issues = self.errs([E("ip", "8.8.8.8"), E("cidr", "banana")])
        self.assertEqual((issues[0]["list"], issues[0]["index"]), ("in_scope", 1))


class TestInternetFacing(unittest.TestCase):
    CASES = [
        ("ip", "8.8.8.8", "public"), ("ip", "10.1.1.1", "internal"), ("ip", "172.16.5.4", "internal"),
        ("ip", "192.168.1.1", "internal"), ("ip", "127.0.0.1", "internal"), ("ip", "169.254.1.1", "internal"),
        ("ip", "100.64.1.1", "internal"), ("ip", "224.0.0.1", "internal"), ("ip", "240.0.0.1", "internal"),
        ("ip", "0.0.0.0", "internal"), ("ip", "::1", "internal"), ("ip", "fd00::1", "internal"),
        ("ip", "fe80::1", "internal"), ("ip", "ff02::1", "internal"), ("ip", "2606:4700::1111", "public"),
        ("ip", "::ffff:10.0.0.1", "internal"),
        ("cidr", "8.8.8.0/24", "public"), ("cidr", "10.0.0.0/8", "internal"), ("cidr", "0.0.0.0/0", "internal"),
        ("cidr", "100.0.0.0/8", "internal"),  # overlaps CGNAT 100.64/10
        ("url", "http://10.0.0.5/", "internal"), ("url", "https://8.8.8.8/", "public"),
        ("url", "https://app.example-public.com/", "public"),
        ("url", "https://intranet.acme-corp.co.uk", "internal"),
        ("hostname", "split.acme-corp.co.uk", "internal"), ("hostname", "shop.acme-corp.co.uk", "public"),
        ("hostname", "localhost", "internal"), ("hostname", "printer.local", "internal"),
        ("hostname", "intranet", "internal"), ("hostname", "nxdomain.example-public.com", "unknown"),
    ]

    def test_cases(self):
        for t, d, want in self.CASES:
            with self.subTest(type=t, data=d):
                self.assertEqual(scope.classify_exposure(t, d, fake_resolver)[0], want)


CRED = {"id": "c1", "label": "admin", "login_url": "https://shop.acme-corp.co.uk/login",
        "username": "admin", "password": "pw"}


class TestHat(unittest.TestCase):
    def errs(self, hat, ins, creds=()):
        return [i for i in scope.check_hat(hat, ins, list(creds), fake_resolver) if i["severity"] == "error"]

    def test_white_accepts_private_and_creds(self):
        self.assertEqual(self.errs("white", [E("cidr", "192.168.1.0/24")], [CRED]), [])

    def test_hat_no_longer_decides_position(self):
        # v4: the hat is knowledge only; private endpoints are a test-position question
        for hat in ("grey", "black"):
            self.assertEqual(self.errs(hat, [E("cidr", "192.168.1.0/24")]), [])

    def test_grey_internal_with_scoped_creds(self):
        # the user's case: grey-box internal test with a provided account
        cred = dict(CRED, login_url="http://10.0.0.5/login")
        self.assertEqual(self.errs("grey", [E("url", "http://10.0.0.5/")], [cred]), [])

    def test_grey_allows_scoped_creds(self):
        self.assertEqual(self.errs("grey", [E("hostname", "shop.acme-corp.co.uk")], [CRED]), [])

    def test_grey_rejects_unassociated_creds(self):
        other = dict(CRED, login_url="https://elsewhere.example-public.com/login")
        e = self.errs("grey", [E("hostname", "shop.acme-corp.co.uk")], [other])
        self.assertIn("not covered", e[0]["message"])
        e = self.errs("grey", [E("hostname", "shop.acme-corp.co.uk")], [dict(CRED, login_url="")])
        self.assertIn("must name the in-scope login URL", e[0]["message"])

    def test_black_rejects_any_credential(self):
        e = self.errs("black", [E("hostname", "shop.acme-corp.co.uk")], [CRED])
        self.assertEqual(e[0]["list"], "keysafe")

class TestPosition(unittest.TestCase):
    PRIVATE = [E("cidr", "192.168.1.0/24"), E("url", "http://10.0.0.5/"), E("hostname", "fileserver.corp")]
    PUBLIC = [E("hostname", "shop.acme-corp.co.uk"), E("ip", "8.8.8.8")]

    def errs(self, pos, ins):
        return [i for i in scope.check_position(pos, ins, fake_resolver) if i["severity"] == "error"]

    def test_external_rejects_private(self):
        e = self.errs("external", self.PRIVATE)
        self.assertEqual([i["index"] for i in e], [0, 1, 2])
        self.assertIn("internet-facing", e[0]["message"])
        self.assertEqual(self.errs("external", self.PUBLIC), [])

    def test_internal_rejects_public(self):
        self.assertEqual(self.errs("internal", self.PRIVATE), [])
        e = self.errs("internal", self.PUBLIC)
        self.assertEqual([i["index"] for i in e], [0, 1])
        self.assertIn("internal endpoints only", e[0]["message"])

    def test_both_accepts_everything(self):
        self.assertEqual(self.errs("both", self.PRIVATE + self.PUBLIC), [])

    def test_unknown_position_rejected(self):
        self.assertEqual(self.errs("sideways", [])[0]["list"], "position")

    def test_unknown_dns_is_warning(self):
        for pos in ("external", "internal"):
            issues = scope.check_position(pos, [E("hostname", "nx.example-public.com")], fake_resolver)
            self.assertEqual([i["severity"] for i in issues], ["warning"])

    def test_migration_default_keeps_old_behaviour(self):
        self.assertEqual([scope.default_position(h) for h in ("white", "grey", "black", None)],
                         ["both", "external", "external", "external"])


if __name__ == "__main__":
    unittest.main()
