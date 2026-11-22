"""T2.2 — RFC 6238 Appendix B test vectors (8 digits, 30 s step)."""
import unittest

import helpers  # noqa: F401
import totp

KEYS = {"SHA1": b"12345678901234567890",
        "SHA256": b"12345678901234567890123456789012",
        "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234"}
VECTORS = [  # time, SHA1, SHA256, SHA512
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


class TestRfc6238(unittest.TestCase):
    def test_vectors(self):
        for t, *codes in VECTORS:
            for algo, want in zip(("SHA1", "SHA256", "SHA512"), codes):
                with self.subTest(t=t, algo=algo):
                    self.assertEqual(totp.totp(KEYS[algo], at=t, digits=8, algo=algo), want)

    def test_parse_bare_and_uri(self):
        p = totp.parse_setup("gezd gnbv gy3t qojq gezd gnbv gy3t qojq")
        self.assertEqual(p["key"], KEYS["SHA1"])
        u = totp.parse_setup("otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
                             "&digits=8&period=60&algorithm=SHA256&issuer=Acme")
        self.assertEqual((u["digits"], u["period"], u["algo"], u["issuer"]), (8, 60, "SHA256", "Acme"))

    def test_rejects_bad_setup(self):
        for bad in ("", "not-base32!!", "GEZDG", "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ",
                    "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=MD5"):
            with self.subTest(bad=bad), self.assertRaises(totp.OtpError):
                totp.parse_setup(bad)


if __name__ == "__main__":
    unittest.main()
