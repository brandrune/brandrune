"""Offline tests for the availability checker. No network: every registry,
WHOIS server and registrar answer is faked.

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills" / "weavenames" / "scripts"))
import weavenames as wn  # noqa: E402

COM = "https://rdap.verisign.com/com/v1/"
RDAP_CT = "application/rdap+json"


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
                ans = queue.pop(0) if len(queue) > 1 else queue[0]
                return ans if len(ans) == 4 else (*ans, RDAP_CT)
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

        with mock.patch.object(wn._opener, "open", fake_urlopen), mock.patch.object(wn, "backoff", lambda *a: None):
            status, _, err, _ = wn.http_get("https://x.test/domain/foo.com")
        self.assertEqual(status, 404)
        self.assertEqual(seq, [])

    def test_persistent_429_returns_none(self):
        calls = []

        def fake_urlopen(req, timeout):
            calls.append(1)
            raise self._http_error(429)

        with mock.patch.object(wn._opener, "open", fake_urlopen), mock.patch.object(wn, "backoff", lambda *a: None):
            status, _, err, _ = wn.http_get("https://x.test/domain/foo.com")
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
}


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
                "tlds": ["com"], "registrar": registrar,
                "names": [entry("hearth", None, com="open"), entry("zenolia", None, com="unknown")]}

    def test_unpriced_open_is_marked_and_explained(self):
        out = wn.render_text(self.doc(), self.doc()["names"], "")
        self.assertIn("open*", out)
        self.assertIn("price was not verified", out)
        self.assertIn("Not counted as open", out)

    def test_html_escapes_the_description(self):
        page = wn.render_html(self.doc())
        self.assertNotIn("</script><b>", page)
        d = self.doc()
        d["description"] = "<!--<script>"
        self.assertNotIn("<!--<script>", wn.render_html(d).split('id="data"')[1])
        self.assertIn("color-scheme: light", page)


class RedirectAndContentTypeTests(unittest.TestCase):
    def test_html_404_is_unknown(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(404, b"<html>Not Found</html>", "", "text/html")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN)

    def test_redirect_is_not_followed(self):
        import email.message
        import urllib.error

        def fake_open(req, timeout):
            h = email.message.Message()
            h["Location"] = "https://elsewhere.test/404"
            raise urllib.error.HTTPError(req.full_url, 302, "Found", h, None)

        with mock.patch.object(wn._opener, "open", fake_open):
            status, _, _, _ = wn.http_get(COM + "domain/foo.com")
        self.assertEqual(status, 302)
        fake = FakeHTTP({COM + "domain/foo.com": [(302, b"", "", "text/html")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN)

    def test_no_redirect_handler_is_installed(self):
        handlers = [type(h).__name__ for h in wn._opener.handlers]
        self.assertIn("_NoRedirect", handlers)

    def test_json_list_is_unknown_not_a_crash(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(200, b"[1, 2]", "")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN)

    def test_http_only_bootstrap_servers_are_dropped(self):
        boot = {"services": [[["kg"], ["http://rdap.example.kg/"]], [["zz"], ["https://rdap.example.zz/"]]]}
        with mock.patch.object(wn, "http_get", lambda url, headers=None: (200, json.dumps(boot).encode(), "", "application/json")), \
             mock.patch.object(wn, "cache_dir", lambda: Path("/nonexistent/weavenames-test")):
            table = wn.load_bootstrap()
        self.assertNotIn("kg", table)
        self.assertEqual(table["zz"], "https://rdap.example.zz/")


class CanaryTests(unittest.TestCase):
    def setUp(self):
        wn._canary.clear()

    def tearDown(self):
        wn._canary.clear()

    def run_with(self, answers, name="foo"):
        fake = FakeHTTP({COM + f"domain/{k}.com": v for k, v in answers.items()})
        with mock.patch.object(wn, "http_get", fake), mock.patch.object(wn, "rdap_base", lambda t: COM):
            return wn.check_domain(name, "com"), fake

    def test_open_is_downgraded_when_no_canary_is_registered(self):
        r, _ = self.run_with({"foo": [(404, b"", "")], "nic": [(404, b"", "")], "google": [(404, b"", "")]})
        self.assertEqual(r["status"], wn.UNKNOWN)
        self.assertIn("sanity check", r["note"])

    def test_either_canary_is_enough(self):
        r, _ = self.run_with({"foo": [(404, b"", "")], "nic": [(404, b"", "")],
                              "google": [(200, rdap_record("google.com"), "")]})
        self.assertEqual(r["status"], wn.OPEN)
        r2, _ = self.run_with({"foo": [(404, b"", "")], "nic": [(200, rdap_record("nic.com"), "")]})
        self.assertEqual(r2["status"], wn.OPEN)

    def test_canary_is_asked_once_per_tld(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(404, b"", "")], COM + "domain/bar.com": [(404, b"", "")],
                         COM + "domain/nic.com": [(200, rdap_record("nic.com"), "")]})
        with mock.patch.object(wn, "http_get", fake), mock.patch.object(wn, "rdap_base", lambda t: COM):
            self.assertEqual(wn.check_domain("foo", "com")["status"], wn.OPEN)
            self.assertEqual(wn.check_domain("bar", "com")["status"], wn.OPEN)
        self.assertEqual(fake.calls.count(COM + "domain/nic.com"), 1)

    def test_a_canary_non_answer_is_not_cached(self):
        r, _ = self.run_with({"foo": [(404, b"", "")], "nic": [(None, b"", "HTTP 429")],
                              "google": [(None, b"", "HTTP 429")]})
        self.assertEqual(r["status"], wn.UNKNOWN)
        self.assertIn("could not run", r["note"])
        self.assertNotIn("com", wn._canary)


class PlainJson404Tests(unittest.TestCase):
    def test_rdap_error_object_as_application_json_is_open(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(404, b'{"errorCode": 404, "title": "Not Found"}', "", "application/json")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.OPEN)

    def test_json_404_without_error_object_is_unknown(self):
        fake = FakeHTTP({COM + "domain/foo.com": [(404, b'{"message": "nope"}', "", "application/json")]})
        with mock.patch.object(wn, "http_get", fake):
            self.assertEqual(wn.check_rdap("foo", "com", COM)["status"], wn.UNKNOWN)


class CertTests(unittest.TestCase):
    def tearDown(self):
        wn._trust.clear()

    def boom(self, name, tld):
        if name == "foo":
            raise wn.CertError("rdap.bad.test", "self signed")
        return wn.result(f"{name}.{tld}", wn.TAKEN)

    def test_one_bad_registry_certificate_is_an_unknown_row(self):
        wn._trust[:] = [True]
        entries = [{"name": "foo", "style": None, "length": 3}, {"name": "bar", "style": None, "length": 3}]
        with mock.patch.object(wn, "check_domain", self.boom):
            wn.run_checks(entries, ["com"], 2, None, progress=False)
        self.assertEqual(entries[0]["domains"]["com"]["status"], wn.UNKNOWN)
        self.assertIn("rdap.bad.test", entries[0]["domains"]["com"]["note"])
        self.assertEqual(entries[1]["domains"]["com"]["status"], wn.TAKEN)

    def test_a_broken_trust_store_stops_the_run(self):
        wn._trust[:] = [False]
        entries = [{"name": "foo", "style": None, "length": 3}]
        with mock.patch.object(wn, "check_domain", self.boom):
            with self.assertRaises(wn.CertError):
                wn.run_checks(entries, ["com"], 1, None, progress=False)


class RealRedirectTests(unittest.TestCase):
    """Through the real opener and a real local server, not a mock."""

    def test_redirect_target_is_never_contacted(self):
        import http.server
        import threading as th
        hits = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path.startswith("/domain/"):
                    self.send_response(302)
                    self.send_header("Location", "/elsewhere")
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.send_header("Content-Type", "application/rdap+json")
                    self.end_headers()
                    self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        t = th.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            base = f"http://127.0.0.1:{srv.server_port}/"
            r = wn.check_rdap("foo", "com", base)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(r["status"], wn.UNKNOWN)
        self.assertEqual(hits, ["/domain/foo.com"])


class HtmlLabelTests(unittest.TestCase):
    def test_page_carries_the_python_label(self):
        names = [entry("hearth", None, com="open")]
        names[0]["domains"]["com"]["registrar"] = {"price": 2400.0, "verified": False}
        doc = {"description": "x", "checked_at": wn.now_iso(), "tlds": ["com"], "registrar": "vercel", "names": names}
        page = wn.render_html(doc)
        data = json.loads(page.split('type="application/json">', 1)[1].split("</script>", 1)[0])
        self.assertEqual(data["names"][0]["domains"]["com"]["label"], "open* $2,400")
        self.assertNotIn("label", names[0]["domains"]["com"])


class LabelTests(unittest.TestCase):
    def test_names_registries_reject(self):
        self.assertFalse(wn.valid_label("ab--cd"))
        self.assertFalse(wn.valid_label("xn--zzzzzz"))
        self.assertTrue(wn.valid_label("xn--bcher-kva"))
        self.assertTrue(wn.valid_label("a-b-c"))

    def test_multi_label_tld_is_refused(self):
        with self.assertRaises(ValueError):
            wn.parse_tlds("com,co.uk")


class PriceLabelTests(unittest.TestCase):
    """The label a user sees, not just the note behind it."""

    def label_after(self, answers):
        v = wn.Vercel("token")
        with mock.patch.object(wn, "http_get", FakeHTTP({wn.VERCEL_API + k: x for k, x in answers.items()})):
            return wn.cell(v.refine(wn.result("foo.com", wn.OPEN), "com")), v

    def test_verified_standard_price_has_no_star(self):
        label, _ = self.label_after({
            "/v1/registrar/domains/foo.com/availability": [(200, b'{"available": true}', "")],
            "/v1/registrar/domains/foo.com/price": [(200, b'{"years": 1, "purchasePrice": 11.25}', "")],
            "/v1/registrar/tlds/com/price": [(200, b'{"years": 1, "purchasePrice": 11.25}', "")],
        })
        self.assertEqual(label, "open $11")

    def test_failed_availability_check_keeps_the_star(self):
        label, _ = self.label_after({"/v1/registrar/domains/foo.com/availability": [(401, b'{}', "")]})
        self.assertEqual(label, "open*")

    def test_failed_standard_price_keeps_the_star_and_is_not_remembered(self):
        label, v = self.label_after({
            "/v1/registrar/domains/foo.com/availability": [(200, b'{"available": true}', "")],
            "/v1/registrar/domains/foo.com/price": [(200, b'{"years": 1, "purchasePrice": 2400}', "")],
            "/v1/registrar/tlds/com/price": [(None, b"", "HTTP 503")],
        })
        self.assertEqual(label, "open* $2,400")
        self.assertNotIn("com", v.base_prices)

    def test_failed_price_lookup_keeps_the_star(self):
        label, _ = self.label_after({
            "/v1/registrar/domains/foo.com/availability": [(200, b'{"available": true}', "")],
            "/v1/registrar/domains/foo.com/price": [(500, b'', "")],
            "/v1/registrar/tlds/com/price": [(200, b'{"purchasePrice": 11.25}', "")],
        })
        self.assertEqual(label, "open*")

    def test_bad_token_falls_back_to_unpriced(self):
        with mock.patch.dict("os.environ", {"VERCEL_TOKEN": "bad"}), \
             mock.patch.object(wn, "http_get", FakeHTTP({wn.VERCEL_API + "/v1/registrar/tlds/com/price": [(401, b"{}", "")]})):
            self.assertIsNone(wn.vercel_checked(["com"], False))
        with mock.patch.dict("os.environ", {"VERCEL_TOKEN": "ok"}), \
             mock.patch.object(wn, "http_get", FakeHTTP({wn.VERCEL_API + "/v1/registrar/tlds/com/price": [(500, b"{}", "")]})):
            self.assertIsNotNone(wn.vercel_checked(["com"], False))


class FailureIsolationTests(unittest.TestCase):
    def test_one_crashing_lookup_becomes_an_unknown_row(self):
        entries = [{"name": "foo", "style": None, "length": 3}, {"name": "bar", "style": None, "length": 3}]

        def boom(name, tld):
            if name == "foo":
                raise KeyError("x")
            return wn.result(f"{name}.{tld}", wn.TAKEN)

        with mock.patch.object(wn, "check_domain", boom):
            wn.run_checks(entries, ["com"], 2, None, progress=False)
        self.assertEqual(entries[0]["domains"]["com"]["status"], wn.UNKNOWN)
        self.assertEqual(entries[1]["domains"]["com"]["status"], wn.TAKEN)

    def test_certificate_failure_stops_without_retrying(self):
        import urllib.error
        calls = []

        def fake_open(req, timeout):
            calls.append(1)
            raise urllib.error.URLError(ssl.SSLCertVerificationError("self signed"))

        with mock.patch.object(wn._opener, "open", fake_open), mock.patch.object(wn, "backoff", lambda *a: None):
            with self.assertRaises(wn.CertError):
                wn.http_get("https://x.test/")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
