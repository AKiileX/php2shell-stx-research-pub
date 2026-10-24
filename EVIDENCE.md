# Evidence summary

This is a compact summary of preserved local records. The results apply to
the exact builds and conditions named here.

## Apache/mod_php

The PHP 8 branch record contains successful `id` output as
`uid=33(www-data)` on exact official PHP 8.3.35, 8.4.26, and 8.5.11 Apache
builds. The accepted historical campaign completed 10 of 18 trials. Each of
the eight misses stopped at the module address disclosure stage.

The strongest WordPress record used PHP 8.4.26, WordPress 7.1.3,
`display_errors=Off`, `output_buffering=4096`, OPcache, five Apache workers,
128M and 8M PHP limits, and the disabled function list in the README. The PoC
snapshot SHA-256 was
`7d7f464dcedf477aa564370279300c289faa00777ea195cfddd401ef8078f905`.
The public `poc.py` has the same exploit implementation. Its introductory
description and one Stage 2 failure message were corrected, so its release
checksum is listed in `SHA256SUMS`.

Three independently fetched `id` receipts used different runtime addresses:

| Receipt | Zend heap base | Loaded libphp base | Result |
|---|---|---|---|
| `sf78593` | `0x76a2c6a00000` | `0x76a2c6c24000` | `uid=33(www-data)` |
| `sb73d8b` | `0x7c8ec6400000` | `0x7c8ec675e000` | `uid=33(www-data)` |
| `s72b263` | `0x7e6ecc800000` | `0x7e6eccb65000` | `uid=33(www-data)` |

Two further short-command receipts contained `www-data`. For the `s72b263`
trial, Apache records show HTTP 404 for the receipt before the run, the two
memory-limit failures, a roughly 5.29 MB disclosure response, HTTP 200 for the
receipt afterward, then the final worker's SIGSEGV. A crash or the response
size alone is not the execution proof.

## PHP-FPM

The controlled Debian PHP 8.4.26 FPM fixture completed an HTTP-only command
chain twice across changing ASLR layouts. One run recovered heap base
`0x7d6dbf000000` and executable base `0x63074b84f000`; another recovered
`0x78af8e000000` and `0x5da45901f000`. Each run checked a unique receipt as
absent before execution and fetched `id` output afterward. The fixture used
custom session endpoints, one FPM worker, 64M memory and 256M POST limits,
visible errors, and no disabled functions. It does not establish RCE on
untouched WordPress/FPM.

## Negative controls and limits

- A matched vulnerable/fixed build comparison showed a 4096-byte follow-up
  cookie and nonzero heap base on PHP 8.4.26, versus a normal 32-byte session
  ID and zero derived heap base on PHP 8.4.27.
- PHP 7.4.33 demonstrated an OOM, stale state consumption, and an Apache
  worker SIGSEGV. No command receipt was produced.
- PHP 8.2.34 reached final dispatch only when runtime addresses were supplied
  locally. No standalone HTTP disclosure and RCE chain was demonstrated.
- The tested startup OOM on FPM retired its worker, preventing the next
  request from consuming that worker's stale state. That does not rule out
  application-time producers.

The original private research archive contains the detailed HTTP, Apache,
debugger, process, and receipt records. This public summary does not treat
classifier refusals, disconnects, crashes, or corrupted cookies as RCE.

## Fresh run of this public package

On 2026-10-24, the bundled lab built from the pinned PHP and WordPress inputs.
The loaded Apache module SHA-256 matched
`57dac347add8738e80393d81c70f5039c9534590f6e8c3ae0eaa258b9d18d6a8`.
An operator-side web probe confirmed the README's PHP settings, including
`output_buffering=4096`; the probe was then removed and returned HTTP 404.

The first new process lifetime produced an OOM but no Stage 2 disclosure
within 24 follow-up attempts. After a WordPress container restart, the
unchanged exploit implementation produced:

```text
pre-receipt /wp-content/uploads/se2d9f8: HTTP 404
heap=0x7943fd800000 libphp=0x7943fdaae000
HTTP_RECEIPT /wp-content/uploads/se2d9f8: HTTP 200
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

After another restart, `-c whoami` used a fresh receipt and produced:

```text
pre-receipt /wp-content/uploads/28: HTTP 404
heap=0x765a17800000 libphp=0x765a17a7c000
HTTP_RECEIPT /wp-content/uploads/28: HTTP 200
www-data
```

Both receipt files were owned by UID and GID 33. Apache logged the final
worker exiting on SIGSEGV after the receipt was served. The differing bases
show fresh runtime address recovery in these two trials. They do not show
reliable execution on every process lifetime.
