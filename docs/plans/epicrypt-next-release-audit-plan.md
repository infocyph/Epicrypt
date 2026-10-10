# Epicrypt 3.2.0 audit and release plan

Updated 2026-10-10. One **3.2.0** release contains all security fixes, quality remediation, optional Runwire integration and documentation changes. No identified change requires a major release.

Status: **Implementation and local PHP QA complete.** Final Alpine deployment acceptance is determined by fresh execution reports and [checks on the current PR head](https://github.com/infocyph/Epicrypt/pull/32/checks). [Draft PR #32](https://github.com/infocyph/Epicrypt/pull/32) remains unmerged and untagged. Merge, tag and publication are user-managed. Historical green runs never certify later changes.

## Governing rules

Follow [PHPForge engineering principles](../../vendor/infocyph/phpforge/resources/engineering-principles.md) and its [agent workflow](../../vendor/infocyph/phpforge/resources/AGENTS.md).

- Preserve correctness, security, public parameter names/call forms, persisted formats and host lifecycle ownership.
- Reproduce defects, retain meaningful regressions, and use the smallest cohesive fix in the existing owner.
- Keep all configured static, mutation, style and complexity gates: class 80/function 12. No suppression, exclusion, vendor edit or budget increase to conceal a failure.
- Measure matched complete HTTP workloads; isolated microbenchmarks support investigation only.
- Retain public persistence contracts, protocol results, enums, catchable exceptions and distinct security boundaries. Remove generated or redundant assets after checking references.

## Resolved audit findings

Severity describes demonstrated behavior and preconditions, not an assigned advisory score. The initial baseline is tag `3.1`, commit `5d10b40527b3e235cf418333bc67e7d12bc02841`.

| Finding | Behavior and implemented fix | Permanent acceptance coverage |
| --- | --- | --- |
| S1 High — single-use JWT replay window | Replay retention previously ended at `exp` while acceptance continued through leeway. Both JWT families now retain through the complete acceptance window with saturated arithmetic; denylist lookup keeps the original expiry. | Expiring stores, symmetric/asymmetric policies, leeway/expiry boundaries, invalid signatures and overflow. |
| S2 Medium — DPoP oldest accepted second | Inclusive maximum-age acceptance could outlive replay retention within that second. Retain through the following second using checked arithmetic. | Oldest accepted proof, second rollover, duplicates, method/URI/nonce/`ath` bindings. |
| S3 High, deployment-dependent — remote address policy | Private/reserved filter flags accepted shared, benchmark, documentation and multicast destinations. Use one public-unicast policy for literals, all DNS answers and mapped IPv6. | Address/CIDR boundaries, mixed answers, public IPv4/IPv6 positives; reject before HTTP invocation. |
| S4 Medium — undeclared Ctype dependency | Development dependencies hid integrity/JOSE failures without Ctype. Replace incidental Ctype calls with native byte/grammar checks. | Production-only `php -n` valid/invalid integrity and actual JWT issue/verify without development packages. |
| S5 Medium — PSR-16 cache keys | Reserved colons and a 78-byte key failed conforming providers. Use a versioned, domain-separated 64-character SHA-256 identity. | Strict PSR-16 key provider; documented cold-cache transition. |
| S6 Medium — JWKS policy isolation | Strict freshness/trust readers reused entries fetched under another policy. Include normalized trust, freshness/stale and resource bounds in cache identity. | Equivalent-policy hits, differing TTL/stale/hosts/bounds, discovery/URI separation, force refresh, malformed entries and cache failures. |
| S7 Medium — stalled remote body | Empty reads without EOF could retain a worker indefinitely. Reject no-progress reads while retaining exact-limit and bounded normal reads. | Unknown sizes, stalled/throwing/truncated bodies, EOF and malformed JSON. |
| Q1 Required — PHPForge quality | Resolve 20 complexity diagnostics and the `JwtPolicy` Rector finding using cohesive guards/private steps and justified collaborators. | Maximum-level PHPStan/Psalm, Rector and all configured structural checks remain unchanged and pass. |
| R1 Required — release trigger | Enable tag events while retaining branch/PR QA and tag-only release routing. | Static routing checks; real tag dispatch remains part of user-managed publication. |

**Q2 excluded:** `doctrine/annotations` abandonment comes through PHPBench/PHPForge's development toolchain. It is non-blocking and explicitly outside Epicrypt remediation. Production dependencies have no advisories or abandoned packages; no audit policy is weakened.

Four additional review findings and a clock-provider edge were reproduced and fixed:

- Live task-local bindings retained discarded contexts. One immutable lookup key plus copied weak binding maps prevents accumulation and preserves earlier sibling isolation. A 20,000-binding probe reduced retained heap from 10,755,104 to 71,640 bytes; the warmed permanent smoke measures about 4.4 KiB.
- SHA/BLAKE integrity hashing now checks cancellation after the final EOF read, including verification paths.
- Stale JWKS expiry is checked after the failed fetch, including elapsed transport time and the exclusive expiry boundary.
- Cache get/set/delete preserve Runwire cancellation, including independently cancelled child requests.
- Caller-supplied clock cancellation is checked when the clock returns or throws, before fresh/stale keys can be accepted or another error can mask cancellation.

Ten pre-fix failures reproduced the initial review findings; six further clock cases cover fresh/stale/expired entries and returning/throwing clocks. The final PHP suite passes **387 tests / 1,770 assertions**. PHPForge processing, detailed QA, release guard, strict local Sphinx and production-only no-Runwire/no-Pathwise/no-Ctype smoke pass.

## Integration and compatibility

- PHP `^8.4`; required extensions: Hash, JSON, OpenSSL and Sodium. CI certifies PHP 8.4/8.5, stable/lowest dependencies and Windows publication.
- Runwire is optional: exact `2.1.1` in development, an explicit suggestion and an unsupported-version conflict. No mandatory production runtime dependency.
- `RunwireExecutionContext` accepts the passed `RuntimeContext`, optional `RequestContext`, optional live `CoroutineScope` and bounded checkpoint interval. Bind inside the owning task and forward the same context, or the three raw host objects, through intermediary libraries.
- `SecretStream`, `FileProtector`, `FileHasher` and `RemoteJwks` accept optional named `context` arguments. Invalid/completed/cancelled bindings fail; absent context retains normal synchronous calls.
- Cooperative yield requires both `RUNWIRE_COROUTINES` and a live scope. Cancellation works without coroutine capability. Regular file/PSR-18 I/O remains synchronous; cryptographic calls are not offloaded.
- Epicrypt never creates workers, starts/stops runtimes, owns event loops, completes host requests or closes host scopes. Cancellation preserves atomic file publication; caller-owned output streams retain host rollback/publication responsibility.
- Host adapters retain HTTP timeout, redirect suppression, connected-socket DNS pinning, durable atomic state, authorization, rate limiting and password-cost responsibilities.
- Pathwise `^4.2` is a development interoperability baseline only. Its wrapper is not required by Epicrypt.
- Node **26.11.1** and exact `jose` **6.2.12** support independent JOSE/OAuth testing. The npm manifests and lockfile are required by CI and excluded from distribution archives.

See the maintained [Runwire guide](../runwire-integration.rst), [remote JOSE guide](../remote-jose-security.rst), [storage contracts](../token-storage.rst), [benchmark guide](../benchmarking.rst) and [release notes](../release-notes-3.2.0.rst).

## Final deployment certification

All release Docker images use explicit version tags without digest pins: `php:8.4.26-fpm-alpine3.24` for HTTP and the persistent process, `nginx:1.30.5-alpine3.24` plus Bash/curl/wrk/procps/coreutils for measurement, and `php:8.4.26-cli-alpine3.24` for AEGIS. CI runner operating systems remain separate from container images. Record the resolved image identities in each measurement report.

Run `benchmarks/docker-host-acceptance.sh` on the user-authorized Docker host. The script records source identities/patch, runtime and image metadata, production lockfile, shared public EC/JWKS fixtures, CPU affinity, FPM/OPcache/proxy configuration, raw trials and live resource samples in `var/docker-host-acceptance/`. Independent exact-head CI uploads the equivalent `docker-host-acceptance` artifact.

Required profile and unchanged budgets:

- Four static FPM workers, identical production dependencies including Runwire 2.1.1, OPcache 128 MiB/JIT off, bounded 128 MiB tmpfs and disabled access logs.
- Separate FPM/proxy/client CPU sets; record actual affinities. Only the fresh CI runner pins its Docker daemon/controller threads; local host daemon configuration is untouched.
- Readiness and 60-second warmup before each comparison. Three alternating trials at concurrency **1, 4, 8**, comparing unbound calls with `3.1` and borrowed calls with pre-review `1b034ec`.
- Each mixed response independently verifies file encryption round trip/integrity, JWT, JWKS miss/hit and borrowed cancellation/ownership. Zero incorrect responses, socket errors or timeouts.
- Reject **>2% median successful RPM loss**, **>5% trial spread**, or **>256 MiB process-tree RSS**. Retain p50/p95/p99 and CPU/memory samples. Local and CI defaults use 60-second measured trials to reduce the noise observed in shorter windows.
- A **300-second** persistent process checks alternating tenant/request state, cancellation, 20,000 discarded scoped bindings and **2 MiB heap-growth** guards. Sample live RSS continuously and verify real FPM replacement with a changed host PID and correct response.

**Historical evidence:** The pre-clock-fence Debian profile passed all six comparisons (unbound -1.604%, -0.503%, +0.940%; borrowed -0.147%, +1.103%, +0.723%), with 643,401 correct responses, zero errors, peak RSS 110,208 KiB and a successful 300-second soak/replacement. Subsequent runs rejected unstable trials; the final-clock local Debian attempt rejected a stable -3.250% unbound concurrency-1 regression. These results are retained as diagnostic history and do not certify Alpine or the final revision. No guard is relaxed by changing images.

Generated graphs, superseded raw local attempts and the verbose historical tracker have been moved out of the workspace after reference checks. Unique audit findings and release requirements are consolidated here; hosted run artifacts and current reports retain execution evidence. This cleanup does not remove CI/test/docs dependencies or public API types.

## Release checklist

- [x] Security and review findings fixed with meaningful pre-fix reproductions and permanent regressions.
- [x] PHPForge processors/detailed QA/release guard and production-minimal smoke pass for the current production source tree `5d0286488c5d60223bc24df0448bc3dac8c6919c`.
- [x] Regenerated Node lockfile, clean npm install/audit and both bidirectional interop checks pass with the upgraded tools; npm reports zero vulnerabilities.
- [x] Cross-checked documentation, complete-example syntax/runtime checks and strict Sphinx pass after cleanup; PHPForge CI and comparator positive/six negative cases pass.
- Require a fresh authorized Alpine host report passing all six RPM comparisons, 300-second soak and worker replacement.
- Require **all** Security & Standards and Documentation checks to pass on the latest committed PR head, including independent Alpine acceptance, PHP 8.4/8.5 stable/lowest, PHPForge acceptance, production smoke, mutation floors, Windows, AEGIS, interoperability/npm audit and benchmarks.
- Leave merge/tag/publication to the user after the blocking gates pass; verify actual tag release dispatch separately.

Completion is determined by successful final execution records, not this document's historical checkpoints. Report local validation, host deployment, exact-head hosted CI and publication state separately.
