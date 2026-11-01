#!/usr/bin/env python3
"""Fail before the GitHub Pages certificate behind Cloudflare takes the site down.

Version 1.0. Owner: ACS project leads.

Cloudflare proxies owaspacs.org in Full (strict) mode, so a browser sees Cloudflare's
certificate and an HTTPS check passes until the origin's lapses and every request gets a
526. This connects to the origin directly. Cloudflare can pick any origin IP, so a bad
certificate on one fails the check, while an unreachable one is skipped.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

DOMAIN = "owaspacs.org"
EDGE_URL = f"https://{DOMAIN}/"
ORIGIN_IPS = ("185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153")
# Three weeks for a lead to see the alarm, turn the proxy off, and watch GitHub renew.
MIN_DAYS_LEFT = 21
TIMEOUT_SECONDS = 10
REMEDY = "Turn the Cloudflare records to DNS only so GitHub can renew, then re-enable the proxy."


def origin_cert(ip: str) -> dict:
    """The certificate at ip, validated against DOMAIN for chain and hostname."""
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((ip, 443), TIMEOUT_SECONDS) as raw:
        with context.wrap_socket(raw, server_hostname=DOMAIN) as tls:
            return tls.getpeercert()


def edge_status() -> int:
    # Cloudflare may challenge urllib's default agent, which would read as an outage.
    request = urllib.request.Request(EDGE_URL, headers={"User-Agent": "acs-monitor"})
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return response.status


def check_origin(connect, now: float, min_days: int = MIN_DAYS_LEFT) -> list[str]:
    days: list[int] = []
    invalid: list[str] = []
    for ip in ORIGIN_IPS:
        try:
            expires = ssl.cert_time_to_seconds(connect(ip)["notAfter"])
            days.append(int((expires - now) // 86400))
        except ssl.SSLCertVerificationError as error:
            invalid.append(f"{ip}: {error.verify_message}")
        except OSError as error:
            print(f"{ip}: skipped, {type(error).__name__}", file=sys.stderr)
    if invalid:
        return [f"{DOMAIN} origin certificate is invalid, days left: unknown. {', '.join(invalid)}. {REMEDY}"]
    if not days:
        return [f"{DOMAIN} days left: unknown. This runner could not reach any origin IP."]
    if min(days) < min_days:
        return [f"{DOMAIN} origin certificate expiring, days left: {min(days)}. {REMEDY}"]
    print(f"{DOMAIN} origin certificate valid, days left: {min(days)}")
    return []


def check_edge(fetch=edge_status) -> list[str]:
    try:
        status = fetch()
    except urllib.error.HTTPError as error:
        status = error.code
    except OSError as error:
        return [f"{DOMAIN} edge: could not reach {EDGE_URL}: {error}"]
    if status == 200:
        return []
    # Only a 526 is Cloudflare rejecting the origin certificate. Other codes have other fixes.
    return [f"{DOMAIN} edge returned {status}, expected 200.{f' {REMEDY}' if status == 526 else ''}"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--min-days", type=int, default=MIN_DAYS_LEFT)
    args = parser.parse_args(argv)
    failures = check_origin(origin_cert, time.time(), args.min_days) + check_edge()
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
