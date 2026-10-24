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
The public `poc.py` preserves that exploit implementation and adds the
validated Apache base-cache path described below. Its current release checksum
is listed in `SHA256SUMS`.

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

## Apache multi-worker base reuse

One successful disclosure was followed by ten Stage 3-only command attempts
using the same heap and libphp bases. All ten returned unique HTTP receipts.
The later commands were handled by Apache replacement workers, including log
PIDs 33, 36, 39, and 48. This showed that the cached bases remained usable
across worker turnover while the same Apache master remained alive.

The cache implementation was then tested across three additional Apache master
lifetimes. Each cycle started with an empty cache and an ASLR-changing restart:

| Cycle | Fresh heap base | Fresh libphp base | Fresh command | Cached commands |
|---|---|---|---|---|
| 1 | `0x7ce697a00000` | `0x7ce697c90000` | `id` | `whoami`, `pwd` |
| 2 | `0x7ff3f4000000` | `0x7ff3f4200000` | `id` | `whoami`, `pwd` |
| 3 | `0x7a51cae00000` | `0x7a51cb14c000` | `id` | `whoami`, `pwd` |

All three fresh disclosures and all six cache-only commands produced
independent 404-before and 200-after receipts. A separate restart control fed
the client bases from the previous master. The stale attempt produced no
receipt, so the client discarded the entry, recovered new bases, and completed
an independently verified `id` execution.

This does not establish that one cache entry works across multiple backend
masters or that the first disclosure will succeed in every existing process
lifetime.

One later disclosure contained two page-aligned module candidates. The real
`zval_ptr_dtor` value appeared 36 times and a false candidate appeared 5
times. The earlier client rejected both merely because two candidates existed.
The selector now accepts a candidate only when it has at least twice the
support and a margin of at least four repetitions over the runner-up. Close
results remain an error. Unit controls covered dominant, single, empty, and
close-candidate cases. A fresh empty-cache run after an ASLR-changing restart
then recovered new bases and returned an independent `ls` receipt.
