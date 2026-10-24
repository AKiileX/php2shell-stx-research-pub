# PHP2Shell STX Research

I have been testing the PHP memory safety issues reported as CVE-2026-109618
and CVE-2026-109619 across builds and deployment styles. This repository is a
small snapshot of the results so far: one working PoC, a reproducible WordPress
lab, and the evidence behind the claims.

I verified HTTP command execution as `www-data` on exact PHP 8.3.35, 8.4.26,
and 8.5.11 Apache/mod_php builds. The current `poc.py` contains two PHP 8.4.26
profiles: the exact Apache build used with WordPress and a separate controlled
FPM fixture. The 8.3 and 8.5 results come from earlier clients and are not
profiles in this script.

## The WordPress test

The main application result used WordPress 7.1.3 and the exact official PHP
8.4.26 Apache/mod_php binary. The HTTP endpoint was WordPress's bundled
`wp-content/index.php` file. It contains no command gadget, address helper,
LFI, or application `unserialize()` call.

The tested web settings were:

| Setting | Value |
|---|---|
| Apache | prefork, five initial workers |
| `display_errors`, `display_startup_errors`, `expose_php` | Off |
| `log_errors` | On |
| `output_buffering` | 4096 |
| `memory_limit`, `post_max_size`, `upload_max_filesize` | 128M, 8M, 2M |
| `max_input_vars`, upload progress, OPcache | 1000, On, On |

The profile also disabled `exec`, `system`, `shell_exec`, `passthru`,
`proc_open`, `popen`, and `pcntl_exec`. Three fresh `id` receipts and two
`whoami` receipts identified the web worker as `www-data`. Receipt paths were
checked as absent before the attempt and fetched afterward. The exact
`libphp.so` SHA-256 was
`57dac347add8738e80393d81c70f5039c9534590f6e8c3ae0eaa258b9d18d6a8`.

These are results for that binary and configuration. WordPress itself did not
provide the execution gadget. Another PHP 8.4.26 package can have different
function offsets and heap behavior.

## How the PoC handles ASLR

The client first recovers a Zend heap address and a live PHP code pointer from
HTTP responses. It uses the known code pointer offset for the matched binary
to calculate the module base loaded in that process. The final stage uses
those fresh addresses with a previously measured heap layout and function
offsets. Successful runs after restarts had different heap and module bases.

This is dynamic runtime address recovery for known profiles. The script does
not derive function offsets or a working heap layout for an arbitrary unknown
PHP build. A PHP version header alone cannot establish binary compatibility.

### Apache worker reuse

The Apache profile now keeps a local cache of the disclosed heap and libphp
bases. Under the tested prefork model, those bases remained valid across the
original workers and workers later forked by the same Apache master. Ten
Stage 3-only executions succeeded after one disclosure, including executions
handled by replacement workers.

The cache is not treated as proof. Every command still needs an independent
receipt. If Apache restarts and ASLR changes, a cached attempt produces no
receipt, the entry is discarded, and the client returns to the disclosure
stages. This restart recovery was tested successfully with different old and
new heap and module bases.

This result is specific to the exact tested prefork profile. A load balancer
with multiple backend masters could route requests to different address
spaces, and first contact with an already-used process lifetime can still miss
Stage 2.

## Current PoC

`poc.py` preserves the validated `poc-stx.py` exploit implementation. The
introductory description and one failure message were corrected for accuracy.
It uses Python's standard library and accepts `-u`, `-c`, `-verify`,
`--profile`, `--base-cache`, and `--no-base-cache`.

- `php84-official-prod-v1` covers the exact Apache/mod_php profile in the
  bundled WordPress lab. The command carrier is calibrated for at most 32
  bytes.
- `debian-php84.26-fpm-unserialize-v1` covers a controlled FPM fixture with
  custom application endpoints. Its fixture is not bundled here, and it is
  not a generic WordPress/FPM profile.

The client dynamically calculates runtime addresses for those profiles. In
`auto` mode it recognizes the special FPM fixture by its endpoint signatures;
otherwise it tries the Apache profile. That fallback does not prove an unknown
server has the same binary. Choose the known profile explicitly when
reproducing a result.

`-verify` creates a fresh `id` receipt for the Apache profile and checks it
over HTTP. On that profile, `-verify` uses its own command rather than the
value of `-c`. Without `-verify`, `-c` supplies the command, with output
capture depending on the endpoint and carrier size. A missing receipt is
reported as a failure, even if a worker crashes.

By default, Apache bases are stored under the user's cache directory. Use
`--no-base-cache` to force a new disclosure attempt, or `--base-cache PATH` to
keep a separate cache for a particular laboratory run.

## Reproduce the Apache result

On an amd64 host with Docker Compose and Python 3.10 or newer:

```sh
sha256sum -c SHA256SUMS
docker compose -f lab/compose.yaml up -d --build
python3 lab/bootstrap.py
python3 poc.py -u http://127.0.0.1:18940/ --profile php84-official-prod-v1 -verify --attempts 24 --follow-attempts 36
```

The lab listens only on `127.0.0.1`. It uses stock WordPress 7.1.3 application
files, a pinned PHP image, five Apache workers, and the PHP settings above.
There is no marker, exploit helper, or debugger endpoint in the lab.
The database and WordPress admin credentials in `lab/` are fixed test values
for this loopback-only fixture. Do not reuse them for a reachable site.

The chain is sensitive to allocation and worker lifetime. A failed attempt
does not undo the verified runs or prove a target is safe. The client reports
the stage where it stopped. After the first successful disclosure, later
commands against the same Apache master can reuse the cached bases and skip
Stages 1 and 2. Verification creates a small receipt file in the target's
public uploads directory. When finished, remove this disposable lab and its
database volume with `docker compose -f lab/compose.yaml down -v`.

See [EVIDENCE.md](EVIDENCE.md) for the recorded runs and [SHA256SUMS](SHA256SUMS)
for the PoC snapshot checksum.

## Still under research

The historical Apache campaign completed 10 of 18 trials across the three
tested PHP 8 branches. All eight misses were at the module disclosure stage.
That ratio describes those trials, not a general success rate.

A later PHP 8.4.26 prefork campaign used three fresh Apache master lifetimes.
All three fresh disclosure runs succeeded, followed by six successful
cache-only commands. These nine results improve repeated execution after one
disclosure, but do not establish reliable first contact with every existing
process lifetime.

A controlled PHP 8.4.26 FPM fixture also reached command execution with fresh
runtime disclosures. Untouched production-style WordPress behind nginx and
multi-worker FPM has not reached RCE in this research. PHP 7.4.33 has a worker
crash result, but no demonstrated command execution. Catpow is a separate
application-dependent session investigation and is not part of this PoC's RCE
claim.

The open problem is broader black-box adaptation: identifying an unknown
binary, finding its internal offsets and compatible heap layout, and handling
frontends and worker routing without a prior profile. None of that is claimed
as solved here.

## Fix and credit

The PHP project lists 8.2.35, 8.3.36, 8.4.27, and 8.5.12 as fixed supported
releases. Use a fixed vendor package or a supported fixed PHP release.

- [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

This work builds on earlier PHP2Shell research, especially 9bie's heap
placement and ASLR work. The reproduction, exact build profiling, deployment
comparisons, reliability measurements, and evidence corrections here are my
contributions.

## Responsible use

This research is for systems you own or have explicit permission to test.
The PoC can exhaust memory, crash PHP workers, and run commands as the web
worker on a matching vulnerable target. Follow the applicable law, program
rules, and disclosure process. Upgrade exposed PHP installations.
