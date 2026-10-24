#!/usr/bin/env python3
"""Install the loopback-only WordPress fixture through its normal installer."""

from __future__ import annotations

import argparse
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def request(url: str, fields: dict[str, str] | None = None) -> tuple[int, bytes]:
    data = None if fields is None else urllib.parse.urlencode(fields).encode("ascii")
    message = urllib.request.Request(
        url,
        data=data,
        headers={"User-Agent": "php2shell-stx-public-lab-bootstrap/1"},
    )
    with urllib.request.urlopen(message, timeout=30) as response:
        return response.status, response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:18940")
    args = parser.parse_args()
    base = args.url.rstrip("/")
    parsed = urllib.parse.urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        parser.error("the bootstrap accepts only a loopback HTTP lab URL")

    install_url = f"{base}/wp-admin/install.php"
    last_error = "not attempted"
    for _ in range(60):
        try:
            status, body = request(install_url)
            if status == 200:
                break
        except (OSError, urllib.error.URLError) as error:
            last_error = str(error)
        time.sleep(0.5)
    else:
        raise RuntimeError(f"WordPress did not become ready: {last_error}")

    if b"data-installed=\"1\"" not in body and b"install.php?step=2" not in body:
        print(f"wordpress already initialized: status={status} bytes={len(body)}")
        return 0

    if b"data-installed=\"1\"" in body:
        status, body = request(f"{install_url}?step=1&language=")
        if b"install.php?step=2" not in body:
            raise RuntimeError("WordPress did not advance from language selection")

    status, body = request(
        f"{install_url}?step=2",
        {
            "weblog_title": "PHP2Shell STX Public Lab",
            "user_name": "labadmin",
            "admin_password": "lab-password-only",
            "admin_password2": "lab-password-only",
            "pw_weak": "on",
            "admin_email": "lab@example.invalid",
            "blog_public": "0",
            "language": "",
        },
    )
    if b"Success!" not in body:
        raise RuntimeError(
            f"WordPress installation failed: status={status} bytes={len(body)}"
        )
    print(f"wordpress installed: status={status} bytes={len(body)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"bootstrap failed: {error}", file=sys.stderr)
        raise SystemExit(1)
