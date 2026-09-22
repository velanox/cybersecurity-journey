"""
Unit tests for the whois module.

Run standalone, no Flask, no test runner beyond unittest itself:
    python -m modules.whois.tests
or
    python -m unittest modules.whois.tests -v
"""

import socket
import threading
import time
import unittest

from .validators import validate_domain, WhoisValidationError
from .servers import get_tld, get_whois_server, IANA_WHOIS_SERVER, COMMON_WHOIS_SERVERS
from .query import (
    query_whois_server, extract_referral, lookup_domain_raw,
    WhoisNetworkError, WhoisTimeoutError,
)
from .parser import parse_whois, is_not_found
from .whois_lookup import lookup_domain
from . import test_fixtures as fx


# ---------------------------------------------------------------------------
# validators.py
# ---------------------------------------------------------------------------

class TestValidateDomain(unittest.TestCase):

    def test_accepts_plain_domain(self):
        self.assertEqual(validate_domain("example.com"), "example.com")

    def test_lowercases_and_strips_whitespace(self):
        self.assertEqual(validate_domain("  EXAMPLE.COM  "), "example.com")

    def test_strips_scheme_and_path(self):
        self.assertEqual(validate_domain("https://example.com/path?x=1"), "example.com")

    def test_strips_port(self):
        self.assertEqual(validate_domain("example.com:8080"), "example.com")

    def test_strips_trailing_dot(self):
        self.assertEqual(validate_domain("example.com."), "example.com")

    def test_accepts_subdomain(self):
        self.assertEqual(validate_domain("sub.example.com"), "sub.example.com")

    def test_accepts_multi_label_tld(self):
        self.assertEqual(validate_domain("example.co.uk"), "example.co.uk")

    def test_accepts_punycode_tld(self):
        self.assertEqual(validate_domain("xn--nxasmq6b.xn--j6w193g"), "xn--nxasmq6b.xn--j6w193g")

    def test_rejects_empty(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("")
        with self.assertRaises(WhoisValidationError):
            validate_domain("   ")
        with self.assertRaises(WhoisValidationError):
            validate_domain(None)

    def test_rejects_email_address(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("user@example.com")

    def test_rejects_missing_tld(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("example")

    def test_rejects_ip_address(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("192.168.1.1")

    def test_rejects_label_starting_or_ending_with_hyphen(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("-example.com")
        with self.assertRaises(WhoisValidationError):
            validate_domain("example-.com")

    def test_rejects_too_long(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("a" * 260 + ".com")

    def test_rejects_single_char_tld(self):
        with self.assertRaises(WhoisValidationError):
            validate_domain("example.c")


# ---------------------------------------------------------------------------
# servers.py
# ---------------------------------------------------------------------------

class TestServerResolution(unittest.TestCase):

    def test_get_tld_simple(self):
        self.assertEqual(get_tld("example.com"), "com")

    def test_get_tld_multi_part(self):
        self.assertEqual(get_tld("example.co.uk"), "co.uk")

    def test_get_tld_subdomain_does_not_confuse_result(self):
        self.assertEqual(get_tld("a.b.example.com"), "com")

    def test_known_tld_returns_specific_server(self):
        self.assertEqual(get_whois_server("example.com"), COMMON_WHOIS_SERVERS["com"])

    def test_multi_part_tld_falls_back_to_last_label(self):
        # "co.uk" isn't itself a table entry, but "uk" is
        self.assertEqual(get_whois_server("example.co.uk"), COMMON_WHOIS_SERVERS["uk"])

    def test_unknown_tld_falls_back_to_iana(self):
        self.assertEqual(get_whois_server("example.totallymadeuptld"), IANA_WHOIS_SERVER)


# ---------------------------------------------------------------------------
# query.py — real socket behavior against a local fake WHOIS server
# ---------------------------------------------------------------------------

def _start_fake_server(response_bytes=b"", delay=0, refuse=False):
    """Starts a tiny real TCP server on 127.0.0.1:<ephemeral>, returns the port."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(("127.0.0.1", 0))
    port = server_sock.getsockname()[1]
    server_sock.listen(1)

    def handle():
        try:
            conn, _ = server_sock.accept()
            conn.recv(4096)
            if delay:
                time.sleep(delay)
            conn.sendall(response_bytes)
            conn.close()
        except OSError:
            pass
        finally:
            server_sock.close()

    threading.Thread(target=handle, daemon=True).start()
    return port


class TestQueryNetwork(unittest.TestCase):

    def test_successful_query_returns_response(self):
        port = _start_fake_server(b"Domain Name: EXAMPLE.COM\r\n")
        response = query_whois_server("127.0.0.1", "example.com", timeout=3, port=port)
        self.assertIn("EXAMPLE.COM", response)

    def test_timeout_raises_whois_timeout_error(self):
        port = _start_fake_server(b"", delay=5)
        with self.assertRaises(WhoisTimeoutError):
            query_whois_server("127.0.0.1", "example.com", timeout=0.3, port=port)

    def test_connection_refused_raises_network_error(self):
        # Port 1 is privileged/unused in this sandbox — nothing listens there.
        with self.assertRaises(WhoisNetworkError):
            query_whois_server("127.0.0.1", "example.com", timeout=1, port=1)

    def test_dns_failure_raises_network_error(self):
        with self.assertRaises(WhoisNetworkError):
            query_whois_server("this-host-does-not-exist.invalid", "example.com", timeout=2)

    def test_extract_referral_variants(self):
        self.assertEqual(extract_referral("refer:        whois.example.test\n"), "whois.example.test")
        self.assertEqual(extract_referral("whois: whois.other.test\n"), "whois.other.test")
        self.assertIsNone(extract_referral("no referral line here"))


# ---------------------------------------------------------------------------
# query.py — lookup_domain_raw composition, via dependency injection
# ---------------------------------------------------------------------------

class TestLookupDomainRaw(unittest.TestCase):

    def test_direct_response_no_referral(self):
        def fake_query(server, query, timeout):
            return "Domain Name: EXAMPLE.COM\nRegistrar: Fake Corp\n"

        result = lookup_domain_raw("example.com", _query_fn=fake_query)
        self.assertIsNone(result["error"])
        self.assertIn("EXAMPLE.COM", result["raw"])

    def test_referral_is_followed(self):
        calls = []

        def fake_query(server, query, timeout):
            calls.append(server)
            if len(calls) == 1:
                return "refer: whois.real-registry.test\n"
            return "Domain Name: EXAMPLE.ZZZ\nRegistrar: Real Registry\n"

        result = lookup_domain_raw("example.zzzmadeup", _query_fn=fake_query)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["server"], "whois.real-registry.test")
        self.assertIn("Real Registry", result["raw"])

    def test_referral_failure_falls_back_to_first_response(self):
        def fake_query(server, query, timeout):
            if server != "whois.real-registry.test":
                return "refer: whois.real-registry.test\n"
            raise WhoisNetworkError("second hop failed")

        result = lookup_domain_raw("example.zzzmadeup", _query_fn=fake_query)
        self.assertIsNotNone(result["error"])
        self.assertIn("refer:", result["raw"])

    def test_direct_network_failure(self):
        def fake_query(server, query, timeout):
            raise WhoisNetworkError("boom")

        result = lookup_domain_raw("example.com", _query_fn=fake_query)
        self.assertEqual(result["error"], "boom")
        self.assertIsNone(result["raw"])

    def test_invalid_domain_raises_before_any_network_call(self):
        calls = []

        def fake_query(server, query, timeout):
            calls.append(1)
            return "should never be reached"

        with self.assertRaises(WhoisValidationError):
            lookup_domain_raw("not a domain!!", _query_fn=fake_query)
        self.assertEqual(len(calls), 0)


# ---------------------------------------------------------------------------
# parser.py
# ---------------------------------------------------------------------------

class TestParser(unittest.TestCase):

    def test_verisign_style(self):
        r = parse_whois(fx.VERISIGN_STYLE)
        self.assertEqual(r["registrar"], "Registrar Corp Inc.")
        self.assertEqual(r["created"], "1995-08-14T04:00:00Z")
        self.assertEqual(r["updated"], "2024-08-14T04:39:36Z")
        self.assertEqual(r["expires"], "2025-08-13T04:00:00Z")
        self.assertEqual(r["status"], ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"])
        self.assertEqual(r["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertFalse(r["not_found"])

    def test_ripe_style(self):
        r = parse_whois(fx.RIPE_STYLE)
        self.assertEqual(r["updated"], "2023-11-02T10:15:00Z")
        self.assertEqual(r["nameservers"], ["ns1.example-hosting.de", "ns2.example-hosting.de"])
        self.assertEqual(r["status"], ["connect"])
        self.assertFalse(r["not_found"])

    def test_jprs_bracket_style(self):
        r = parse_whois(fx.JPRS_STYLE)
        self.assertEqual(r["created"], "2001-04-01")
        self.assertEqual(r["updated"], "2024-04-01")
        self.assertEqual(r["status"], ["Active"])
        self.assertEqual(r["nameservers"], ["ns1.example.jp", "ns2.example.jp"])

    def test_not_found_variant_1(self):
        r = parse_whois(fx.NOT_FOUND_STYLE)
        self.assertTrue(r["not_found"])
        self.assertIsNone(r["registrar"])

    def test_not_found_variant_2(self):
        r = parse_whois(fx.NOT_FOUND_STYLE_2)
        self.assertTrue(r["not_found"])

    def test_available_domain_reported_as_not_found(self):
        r = parse_whois(fx.AVAILABLE_STYLE)
        self.assertTrue(r["not_found"])

    def test_empty_response_reported_as_not_found(self):
        r = parse_whois(fx.EMPTY_RESPONSE)
        self.assertTrue(r["not_found"])

    def test_malformed_response_stays_structured(self):
        r = parse_whois(fx.MALFORMED_RESPONSE)
        self.assertFalse(r["not_found"])  # no not-found marker present
        self.assertIsNone(r["registrar"])
        self.assertEqual(r["status"], [])
        self.assertEqual(r["nameservers"], [])

    def test_redacted_privacy_still_extracts_non_personal_fields(self):
        r = parse_whois(fx.REDACTED_PRIVACY_STYLE)
        self.assertEqual(r["registrar"], "Privacy Registrar LLC")
        self.assertEqual(r["created"], "2020-01-15T00:00:00Z")
        self.assertEqual(r["nameservers"], ["ns1.privacydns.com", "ns2.privacydns.com"])
        self.assertFalse(r["not_found"])

    def test_is_not_found_helper_matches_parse_whois(self):
        self.assertTrue(is_not_found(fx.NOT_FOUND_STYLE))
        self.assertFalse(is_not_found(fx.VERISIGN_STYLE))


# ---------------------------------------------------------------------------
# whois_lookup.py — full assembly
# ---------------------------------------------------------------------------

class TestLookupDomain(unittest.TestCase):

    RESULT_KEYS = {"domain", "registrar", "created", "updated", "expires",
                   "status", "nameservers", "raw", "error", "not_found"}

    def _fake_lookup(self, raw_text=None, error=None, server="whois.example-registry.test"):
        def fn(domain, timeout):
            clean = validate_domain(domain)
            return {"domain": clean, "server": server, "raw": raw_text, "error": error}
        return fn

    def test_valid_domain_full_result(self):
        result = lookup_domain("example.com", _lookup_fn=self._fake_lookup(fx.VERISIGN_STYLE))
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["registrar"], "Registrar Corp Inc.")
        self.assertIsNone(result["error"])
        self.assertFalse(result["not_found"])
        self.assertEqual(result["raw"], fx.VERISIGN_STYLE)

    def test_invalid_domain_raises(self):
        with self.assertRaises(WhoisValidationError):
            lookup_domain("not a domain!!", _lookup_fn=self._fake_lookup(fx.VERISIGN_STYLE))

    def test_nonexistent_domain(self):
        result = lookup_domain("nothere123456.com", _lookup_fn=self._fake_lookup(fx.NOT_FOUND_STYLE))
        self.assertTrue(result["not_found"])
        self.assertIsNone(result["error"])
        self.assertIsNone(result["registrar"])

    def test_masked_redacted_data(self):
        result = lookup_domain("privatedomain.com", _lookup_fn=self._fake_lookup(fx.REDACTED_PRIVACY_STYLE))
        self.assertEqual(result["registrar"], "Privacy Registrar LLC")
        self.assertEqual(result["nameservers"], ["ns1.privacydns.com", "ns2.privacydns.com"])

    def test_timeout_reported_as_error_not_exception(self):
        result = lookup_domain(
            "example.com",
            _lookup_fn=self._fake_lookup(error="Timed out waiting for a response from whois.verisign-grs.com."),
        )
        self.assertIn("Timed out", result["error"])
        self.assertIsNone(result["registrar"])
        self.assertEqual(result["status"], [])

    def test_unexpected_response_stays_structured(self):
        result = lookup_domain("example.com", _lookup_fn=self._fake_lookup(fx.MALFORMED_RESPONSE))
        self.assertIsNone(result["error"])
        self.assertFalse(result["not_found"])
        self.assertIsNone(result["registrar"])
        self.assertEqual(result["raw"], fx.MALFORMED_RESPONSE)

    def test_multiple_tlds_produce_consistent_results(self):
        cases = [
            ("example.com", fx.VERISIGN_STYLE),
            ("example.de", fx.RIPE_STYLE),
            ("example.jp", fx.JPRS_STYLE),
        ]
        for domain, raw in cases:
            with self.subTest(domain=domain):
                result = lookup_domain(domain, _lookup_fn=self._fake_lookup(raw))
                self.assertEqual(set(result.keys()), self.RESULT_KEYS)
                self.assertEqual(result["domain"], domain)
                self.assertIsNone(result["error"])

    def test_result_structure_always_consistent(self):
        scenarios = [
            self._fake_lookup(fx.VERISIGN_STYLE),
            self._fake_lookup(fx.NOT_FOUND_STYLE),
            self._fake_lookup(error="some network failure"),
            self._fake_lookup(fx.MALFORMED_RESPONSE),
            self._fake_lookup(fx.REDACTED_PRIVACY_STYLE),
        ]
        for fn in scenarios:
            result = lookup_domain("example.com", _lookup_fn=fn)
            self.assertEqual(set(result.keys()), self.RESULT_KEYS)
            self.assertIsInstance(result["status"], list)
            self.assertIsInstance(result["nameservers"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)