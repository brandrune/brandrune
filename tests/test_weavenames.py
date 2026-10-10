"""Offline tests for the availability checker. No network: every registry,
WHOIS server and registrar answer is faked.

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills" / "weavenames" / "scripts"))
import weavenames as wn  # noqa: E402

COM = "https://rdap.verisign.com/com/v1/"


def rdap_record(domain: str, statuses=(), nameservers=()) -> bytes:
    return json.dumps({
        "objectClassName": "domain",
        "ldhName": domain.upper(),
        "status": list(statuses),
        "nameservers": [{"ldhName": n} for n in nameservers],
        "events": [{"eventAction": "expiration", "eventDate": "2027-03-01T00:00:00Z"}],
    }).encode()


class FakeHTTP:
    """Maps URL to a list of (status, body) answers, consumed in order."""

    def __init__(self, answers: dict[str, list[tuple]]) -> None:
        self.answers = {k: list(v) for k, v in answers.items()}
        self.calls: list[str] = []

    def __call__(self, url, headers=None):
        self.calls.append(url)
        for prefix, queue in self.answers.items():
            if url.split("?")[0] == prefix:
                return queue.pop(0) if len(queue) > 1 else queue[0]
        raise AssertionError(f"unexpected URL {url}")


class RdapTests(unittest.TestCase):
    def test_registry_404_is_open(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(404, b"", "")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.OPEN)
        self.assertEqual(r["registry"]["answer"], 404)
        self.assertEqual(r["registry"]["source"], COM + "domain/foo.com")

    def test_record_is_taken(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(200, rdap_record("foo.com", nameservers=["a.ns.cloudflare.com"]), "")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.TAKEN)
        self.assertEqual(r["expires"], "2027-03-01")

    def test_parking_nameservers_are_parked(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(200, rdap_record("foo.com", nameservers=["ns1.sedoparking.com"]), "")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.PARKED)

    def test_parking_match_is_by_suffix_not_substring(self):
        self.assertIsNone(wn.parked_by(["ns1.notdan.com"]))
        self.assertEqual(wn.parked_by(["ns1.dan.com"]), "dan.com")

    def test_pending_delete_is_expiring(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(200, rdap_record("foo.com", statuses=["pending delete"]), "")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.EXPIRING)

    def test_proxy_404_without_a_server_is_unknown(self):
        body = json.dumps({"errorCode": 404, "title": "No RDAP service is available for this resource"}).encode()
        fake = FakeHTTP({COM + "domain/foo.com": [(404, body, "")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.UNKNOWN)

    def test_no_answer_is_unknown_never_open(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(None, b"", "HTTP 429")]})
        with mock.patch.object(wn, "http_get", fake):
            r = wn.check_rdap("foo", "com", COM)
        self.assertEqual(r["status"], wn.UNKNOWN)

    def test_other_http_codes_are_unknown(self):
        for code in (400, 403, 301):
            fake = FakeHTTP({COM + "domain/foo.com": [(code, b"", "")]})
            with mock.patch.object(wn, "http_get", fake):
                self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN, code)

    def test_200_that_is_not_a_domain_record_is_unknown(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(200, b'{"hello": "world"}', "")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN)


class RetryTests(unittest.TestCase):
    def _http_error(self, code, retry_after=None):
        import email.message
        import urllib.error
        h = email.message.Message()
        if retry_after:
            h["Retry-After"] = retry_after
        return urllib.error.HTTPError("https://x.test/", code, "err", h, None)

    def test_429_then_404_retries_and_answers(self):
        seq = [self._http_error(429), self._http_error(404)]

        def fake_urlopen(req, timeout):
            raise seq.pop(0)

        with mock.patch("urllib.request.urlopen", fake_urlopen), mock.patch.object(wn, "backoff", lambda *a: None):
            status, _, err = wn.http_get("https://x.test/domain/foo.com")
        self.assertEqual(status, 404)
        self.assertEqual(seq, [])

    def test_persistent_429_returns_none(self):
        calls = []

        def fake_urlopen(req, timeout):
            calls.append(1)
            raise self._http_error(429)

        with mock.patch("urllib.request.urlopen", fake_urlopen), mock.patch.object(wn, "backoff", lambda *a: None):
            status, _, err = wn.http_get("https://x.test/domain/foo.com")
        self.assertIsNone(status)
        self.assertEqual(len(calls), wn.RETRIES)
        self.assertIn("429", err)


class WhoisTests(unittest.TestCase):
    def test_not_found_is_open(self):
        with mock.patch.object(wn, "whois_query", lambda s, q: ("Domain not found.\n>>> Last update <<<\n", "")):
            self.assertEqual(wn.check_whois("foo", "io")["status"], wn.OPEN)

    def test_record_is_taken(self):
        reply = "Domain Name: foo.io\nRegistry Domain ID: X\nCreation Date: 2002-10-01T01:00:00Z\n"
        with mock.patch.object(wn, "whois_query", lambda s, q: (reply, "")):
            self.assertEqual(wn.check_whois("foo", "io")["status"], wn.TAKEN)

    def test_dot_so_not_found_echoes_the_name_and_is_still_open(self):
        reply = "Domain Name: foo.so\nThe queried object does not exist: No Object Found\n"
        with mock.patch.object(wn, "whois_query", lambda s, q: (reply, "")):
            self.assertEqual(wn.check_whois("foo", "so")["status"], wn.OPEN)

    def test_unrecognized_reply_is_unknown(self):
        with mock.patch.object(wn, "whois_query", lambda s, q: ("Query rate exceeded, try later\n", "")):
            self.assertEqual(wn.check_whois("foo", "io")["status"], wn.UNKNOWN)

    def test_reply_matching_both_is_unknown(self):
        reply = "Domain not found.\nCreation Date: 2002-10-01\n"
        with mock.patch.object(wn, "whois_query", lambda s, q: (reply, "")):
            self.assertEqual(wn.check_whois("foo", "io")["status"], wn.UNKNOWN)

    def test_no_reply_is_unknown(self):
        with mock.patch.object(wn, "whois_query", lambda s, q: (None, "timeout")):
            self.assertEqual(wn.check_whois("foo", "io")["status"], wn.UNKNOWN)

    def test_unsupported_tld_is_unknown(self):
        with mock.patch.object(wn, "rdap_base", lambda t: None):
            self.assertEqual(wn.check_domain("foo", "zzzz")["status"], wn.UNKNOWN)


class VercelTests(unittest.TestCase):
    def setUp(self):
        self.v = wn.Vercel("token")

    def _with(self, answers):
        return mock.patch.object(wn, "http_get", FakeHTTP({wn.VERCEL_API + k: v for k, v in answers.items()}))

    def test_standard_price_stays_open(self):
        with self._with({
            "/v1/registrar/domains/foo.com/availability": [(200, b'{"available": true}', "")],
            "/v1/registrar/domains/foo.com/price": [(200, b'{"years": 1, "purchasePrice": 11.25}', "")],
            "/v1/registrar/tlds/com/price": [(200, b'{"years": 1, "purchasePrice": 11.25}', "")],
        }):
            r = self.v.refine(wn.result("foo.com", wn.OPEN), "com")
        self.assertEqual(r["status"], wn.OPEN)
        self.assertEqual(r["registrar"]["price"], 11.25)

    def test_high_price_is_premium(self):
        with self._with({
            "/v1/registrar/domains/foo.com/availability": [(200, b'{"available": true}', "")],
            "/v1/registrar/domains/foo.com/price": [(200, b'{"years": 1, "purchasePrice": 2400}', "")],
            "/v1/registrar/tlds/com/price": [(200, b'{"years": 1, "purchasePrice": 11.25}', "")],
        }):
            r = self.v.refine(wn.result("foo.com", wn.OPEN), "com")
        self.assertEqual(r["status"], wn.PREMIUM)

    def test_unavailable_at_registrar_is_reserved(self):
        with self._with({"/v1/registrar/domains/foo.com/availability": [(200, b'{"available": false}', "")]}):
            r = self.v.refine(wn.result("foo.com", wn.OPEN), "com")
        self.assertEqual(r["status"], wn.RESERVED)

    def test_registrar_failure_keeps_registry_answer_and_says_so(self):
        with self._with({"/v1/registrar/domains/foo.com/availability": [(403, b'{"error": "forbidden"}', "")]}):
            r = self.v.refine(wn.result("foo.com", wn.OPEN), "com")
        self.assertEqual(r["status"], wn.OPEN)
        self.assertIn("not verified", r["note"])


class InputTests(unittest.TestCase):
    def test_parse_names_styles_and_junk(self, tmp=None):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("Fretwise compound\nhearth  real-word\n# comment\nbad name!\nhearth\n-nope\nfoo.com\n")
        entries, bad = wn.read_names(f.name)
        self.assertEqual([e["name"] for e in entries], ["fretwise", "hearth", "foo"])
        self.assertEqual(entries[0]["style"], "compound")
        self.assertEqual(len(bad), 2)

    def test_parse_tlds(self):
        self.assertEqual(wn.parse_tlds(None), ["com"])
        self.assertEqual(wn.parse_tlds(".com, ai,com"), ["com", "ai"])


def ns(**kw):
    base = dict(available_only=False, open=None, any_open=False, min_len=0, max_len=0,
                include=None, exclude=None, style=None, limit=0, html=None)
    base.update(kw)
    return argparse.Namespace(**base)


def entry(name, style, **statuses):
    return {"name": name, "style": style, "length": len(name),
            "domains": {t: {"domain": f"{name}.{t}", "status": s} for t, s in statuses.items()},
            "extras": {}}


class FilterTests(unittest.TestCase):
    names = [
        entry("hearth", "real-word", com="open", ai="taken"),
        entry("hearthly", "suffix", com="taken", ai="open"),
        entry("strumdaily", "compound", com="open", ai="open"),
        entry("zenolia", "invented", com="unknown", ai="open"),
    ]
    tlds = ["com", "ai"]

    def names_for(self, **kw):
        return [e["name"] for e in wn.apply_filters(self.names, self.tlds, ns(**kw))]

    def test_available_only_uses_first_tld_and_drops_unknown(self):
        self.assertEqual(self.names_for(available_only=True), ["hearth", "strumdaily"])

    def test_open_on_several(self):
        self.assertEqual(self.names_for(open="com,ai"), ["strumdaily"])

    def test_length(self):
        self.assertEqual(self.names_for(max_len=7), ["hearth", "zenolia"])
        self.assertEqual(self.names_for(min_len=8), ["hearthly", "strumdaily"])

    def test_include_exclude_style(self):
        self.assertEqual(self.names_for(include=["hearth"]), ["hearth", "hearthly"])
        self.assertEqual(self.names_for(include=["hearth"], exclude=["ly"]), ["hearth"])
        self.assertEqual(self.names_for(style="compound,invented"), ["strumdaily", "zenolia"])

    def test_sort_puts_open_primary_first_then_more_open(self):
        ordered = sorted(self.names, key=lambda e: wn.sort_key(e, self.tlds))
        self.assertEqual([e["name"] for e in ordered], ["strumdaily", "hearth", "hearthly", "zenolia"])


class RenderTests(unittest.TestCase):
    def doc(self, registrar=None):
        return {"tool": "t", "description": "a </script><b>test</b>", "checked_at": "2026-10-10T12:00:00+00:00",
                "tlds": ["com"], "extras": [], "registrar": registrar,
                "names": [entry("hearth", None, com="open"), entry("zenolia", None, com="unknown")]}

    def test_unpriced_open_is_marked_and_explained(self):
        out = wn.render_text(self.doc(), self.doc()["names"], "")
        self.assertIn("open*", out)
        self.assertIn("Price not checked", out)
        self.assertIn("Not counted as open", out)

    def test_html_escapes_the_description(self):
        page = wn.render_html(self.doc())
        self.assertNotIn("</script><b>", page)
        self.assertIn("color-scheme: light", page)


class ReuseTests(unittest.TestCase):
    def test_reuses_fresh_answers_and_rechecks_stale_and_unknown(self):
        import tempfile
        fresh = wn.now_iso()
        prior = {"names": [
            {"name": "hearth", "domains": {"com": {"status": "taken", "registry": {"at": fresh}}}},
            {"name": "zenolia", "domains": {"com": {"status": "unknown", "registry": {"at": fresh}}}},
            {"name": "old", "domains": {"com": {"status": "open", "registry": {"at": "2020-01-01T00:00:00+00:00"}}}},
            {"name": "cheap", "domains": {"com": {"status": "open", "registry": {"at": fresh}}}},
        ]}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(prior, f)
        entries = [{"name": n, "style": None, "length": len(n)} for n in ("hearth", "zenolia", "old", "cheap", "new")]
        self.assertEqual(wn.reuse_results(entries, f.name, priced=True), 1)
        self.assertEqual(entries[0]["domains"]["com"]["status"], "taken")
        for e in entries[1:]:
            self.assertNotIn("com", e.get("domains", {}))
        entries = [{"name": "cheap", "style": None, "length": 5}]
        self.assertEqual(wn.reuse_results(entries, f.name, priced=False), 1)


if __name__ == "__main__":
    unittest.main()
