"""Pins the origin certificate check. Fake connections stand in for the network."""
from __future__ import annotations

import ssl
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import check_origin_cert as check  # noqa: E402

NOW = ssl.cert_time_to_seconds("Nov  1 00:00:00 2026 GMT")
HEALTHY = {"notAfter": "Jan 30 01:38:42 2027 GMT"}
AT_THRESHOLD = {"notAfter": "Nov 22 00:00:00 2026 GMT"}
NEAR_EXPIRY = {"notAfter": "Nov 21 23:59:59 2026 GMT"}
EXPIRED = {"notAfter": "Oct 31 00:00:00 2026 GMT"}


def origin(*results):
    """A connection that plays one result per IP, raising the ones that are errors."""
    plays = iter(results)

    def connect(_ip):
        result = next(plays)
        if isinstance(result, Exception):
            raise result
        return result

    return connect


def everywhere(result):
    return origin(*[result] * len(check.ORIGIN_IPS))


def hostname_mismatch() -> ssl.SSLCertVerificationError:
    error = ssl.SSLCertVerificationError("hostname mismatch")
    error.verify_message = "Hostname mismatch, certificate is not valid for 'owaspacs.org'."
    return error


def assert_names_the_fix(failures: list[str], days: str) -> None:
    assert len(failures) == 1
    assert check.DOMAIN in failures[0]
    assert f"days left: {days}" in failures[0]
    assert check.REMEDY in failures[0]
    assert "DNS only" in check.REMEDY


def test_healthy_certificate_passes():
    assert check.check_origin(everywhere(HEALTHY), NOW) == []


def test_exactly_the_threshold_passes():
    assert check.check_origin(everywhere(AT_THRESHOLD), NOW) == []


def test_near_expiry_fails_one_second_under_the_threshold():
    assert_names_the_fix(check.check_origin(everywhere(NEAR_EXPIRY), NOW), "20")


def test_expired_fails_with_negative_days():
    assert_names_the_fix(check.check_origin(everywhere(EXPIRED), NOW), "-1")


def test_invalid_chain_or_hostname_fails_with_the_reason():
    failures = check.check_origin(everywhere(hostname_mismatch()), NOW)
    assert_names_the_fix(failures, "unknown")
    assert "Hostname mismatch" in failures[0]


def test_one_bad_ip_fails_because_cloudflare_can_pick_it():
    connect = origin(HEALTHY, HEALTHY, hostname_mismatch(), HEALTHY)
    assert_names_the_fix(check.check_origin(connect, NOW), "unknown")


def test_worst_certificate_decides_the_days_left():
    connect = origin(HEALTHY, NEAR_EXPIRY, HEALTHY, HEALTHY)
    assert_names_the_fix(check.check_origin(connect, NOW), "20")


def test_unreachable_ips_are_skipped_while_one_answers():
    connect = origin(TimeoutError(), OSError("refused"), TimeoutError(), HEALTHY)
    assert check.check_origin(connect, NOW) == []


def test_no_reachable_ip_fails_without_blaming_the_certificate():
    failures = check.check_origin(everywhere(TimeoutError()), NOW)
    assert len(failures) == 1
    assert "could not reach" in failures[0]
    assert check.REMEDY not in failures[0]


def test_threshold_is_the_argument_when_given():
    assert_names_the_fix(check.check_origin(everywhere(HEALTHY), NOW, min_days=91), "90")


def test_edge_200_passes():
    assert check.check_edge(lambda: 200) == []


def test_edge_526_fails_with_the_remedy():
    def fetch():
        raise urllib.error.HTTPError(check.EDGE_URL, 526, "Invalid SSL certificate", None, None)

    failures = check.check_edge(fetch)
    assert len(failures) == 1
    assert "526" in failures[0]
    assert check.DOMAIN in failures[0]
    assert check.REMEDY in failures[0]


def test_edge_503_fails_without_the_certificate_remedy():
    failures = check.check_edge(lambda: 503)
    assert "503" in failures[0]
    assert check.REMEDY not in failures[0]


def test_edge_network_error_fails():
    def fetch():
        raise urllib.error.URLError("no route")

    assert "could not reach" in check.check_edge(fetch)[0]


@pytest.mark.parametrize(
    ("failures", "code"),
    [([], 0), (["origin down"], 1)],
)
def test_main_exits_nonzero_only_on_failure(monkeypatch, capsys, failures, code):
    monkeypatch.setattr(check, "check_origin", lambda *_args, **_kwargs: failures)
    monkeypatch.setattr(check, "check_edge", lambda *_args: [])
    assert check.main([]) == code
    if failures:
        assert "origin down" in capsys.readouterr().err


def test_main_still_reports_the_edge_when_the_origin_fails(monkeypatch, capsys):
    monkeypatch.setattr(check, "check_origin", lambda *_args, **_kwargs: ["origin down"])
    monkeypatch.setattr(check, "check_edge", lambda *_args: ["edge down"])
    assert check.main([]) == 1
    errors = capsys.readouterr().err
    assert "origin down" in errors
    assert "edge down" in errors


def test_main_passes_the_forced_threshold_through(monkeypatch):
    seen = {}

    def check_origin(_connect, _now, min_days):
        seen["min_days"] = min_days
        return []

    monkeypatch.setattr(check, "check_origin", check_origin)
    monkeypatch.setattr(check, "check_edge", lambda *_args: [])
    check.main(["--min-days", "500"])
    assert seen == {"min_days": 500}
