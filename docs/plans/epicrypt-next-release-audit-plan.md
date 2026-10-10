# Epicrypt audit and next-release plan

Date: 2026-10-10, Asia/Dhaka. Status: audit complete; remediation and optional integration are planned, not implemented.

## Implementation tracker

Status: **In progress**. Draft PR: [#32](https://github.com/infocyph/Epicrypt/pull/32). Update each row only after a committed change and recorded QA evidence. Never treat the audited baseline as final release certification.

| Batch | Scope | Implementation | Focused QA | Commit / evidence |
| --- | --- | --- | --- | --- |
| 1 | S1–S3 JWT/DPoP replay and remote JOSE address security | Pending | Pending | — |
| 2 | S4–S7 integrity, PSR-16 cache, remote reads | Pending | Pending | — |
| 3 | Q1 complexity and Rector remediation | Pending | Pending | — |
| 4 | Optional Runwire 2.1.1 integration | Pending | Pending | — |
| 5 | Pathwise 4.2/docs/release automation R1 | Pending | Pending | — |
| 6 | Final QA, interoperability, performance and release guard | Pending | Pending | — |

**R1 — Release workflow trigger (blocking):** `.github/workflows/security-standards.yml` has a tag-only `release` job but its push trigger filters only branches. Explicitly enable `push.tags` without disabling branch/PR QA. Check workflow trigger behavior before tagging.

## Decision and governing rules

Target one **3.2.0** release containing the full planned change set: S1-S7 security/correctness fixes, Q1 quality remediation, additive Runwire 2.1.1 support, Pathwise 4.2 integration baseline and affected documentation. Runwire support is part of the release scope; using it remains optional for consumers. All applicable fix and integration gates must pass before releasing. No finding currently requires a 4.0 release.

Follow [PHPForge engineering principles](../../vendor/infocyph/phpforge/resources/engineering-principles.md) and [agent workflow](../../vendor/infocyph/phpforge/resources/AGENTS.md). In particular:

- Correctness, security, public contracts and host lifecycle ownership precede performance and structural simplification.
- Reproduce each defect, add a meaningful regression, make the smallest cohesive fix, and run the configured gates.
- Preserve public parameter names, existing call forms, key-purpose boundaries and wire formats. Changes to unsafe acceptance are security fixes; document them.
- Prefer changes in existing owners and private methods. Justify any new production type by a real boundary or lifecycle responsibility.
- Keep PHPStan at its active maximum level and cognitive-complexity limits of class 80/function 12. No suppression, baseline expansion, exclusions or threshold increases.
- Measure meaningful hot-path changes on matching environments. Component microbenchmarks do not prove host RPM or asynchronous behavior.
- Keep the author's existing `composer.json` and `.gitignore` edits intact.

## Audited baseline and evidence

- Branch: `feature/runwire-2.1`; HEAD/tag `3.1`: `5d10b40527b3e235cf418333bc67e7d12bc02841`.
- Working tree already changed PHP requirement to `^8.4` and adjusted `.gitignore`. The audit adds only this plan.
- Inventory: 287 tracked production source files. Review covered dependency/platform declarations, source and tests at security-sensitive boundaries, all library domains through the full suite, protocol interoperability automation, documentation and release automation. Graphify supplied navigation; findings were verified in source/runtime probes.
- Local runtime: PHP 8.5.4; PHPForge `dev-main f274e78`; phpseclib 4.0.2; Pathwise 4.2.
- Live Composer metadata confirms Runwire 2.1.1 at `745b1c2bd7caa56aa5abf6d742c1aa8318fec494` and Pathwise 4.2 at `f37e99ae41fbb9ab5c632beef266f146a4dc662c`. Inspected Runwire context/scope APIs match that tag.

| Check | Current result |
| --- | --- |
| `composer ic:doctor`, `ic:list-config`, `ic:active-config` | Healthy; inspected active PHPForge configuration |
| `composer validate --strict` | Pass |
| `composer ic:tests` | 11 gates pass; PHPStan and Rector fail |
| `composer ic:test:code` | 299 passed, 1,582 assertions; includes current Pathwise 4.2 interoperability |
| PHPStan | 20 cognitive-complexity diagnostics, detailed below |
| Psalm security, Deptrac, Pint, PHPCS, syntax/reference/duplicate/comment/skip checks, Composer normalization | Pass in the aggregate suite |
| Rector dry run | One required change in `JwtPolicy::acceptsType()` |
| Live `composer audit --locked --format=json` | Zero advisories; abandoned `doctrine/annotations` in development dependency tree; exit 1 |
| Live `composer audit --locked --no-dev --format=json` | Pass; zero advisories and abandoned production dependencies |
| Isolated production `composer install --no-dev --prefer-dist --no-interaction --no-progress --optimize-autoloader` | Pass; eight production packages, no Pathwise/PHPForge |
| Production `tests/Smoke/core-no-pathwise.php` | Pass with normal PHP and `php -n`; misses the Ctype-dependent paths in S4 |
| `composer ic:bench:quick` | 43 subjects; zero failures/errors; supporting microbenchmark evidence only |
| `php benchmarks/authentication.php` | Seven operation scenarios pass; 2,000 repeated PAT validations show zero PHP heap growth, below existing 2 MiB guard |
| Hosted historical HEAD checks | Latest listed Security & Standards run [37174237331](https://github.com/infocyph/Epicrypt/actions/runs/37174237331) and listed Documentation run [35521921808](https://github.com/infocyph/Epicrypt/actions/runs/35521921808) succeeded on baseline SHA; they do not certify this working tree, today's dependency snapshot, or future fixes |

Node and Sphinx are unavailable locally, so independent Node JOSE/OAuth interop, npm audit and the strict Sphinx build were not rerun. PHP 8.4, Windows publication, the special AEGIS lane and mutation floors also require fresh validation after implementation. The local tag is confirmed; `gh release view 3.1` found no published GitHub release with that exact tag. No new tag/release was created.

Temporary evidence from this audit: `/tmp/epicrypt-audit-quality.log`, `/tmp/epicrypt-pest.log`, `/tmp/epicrypt-audit-probes.php`, `/tmp/epicrypt-audit-probes.json`, `/tmp/epicrypt-production-boundaries.php`, `/tmp/epicrypt-production-install.log`, `/tmp/epicrypt-authentication-evidence.json`, `/tmp/epicrypt-phpbench.log`. Convert the focused probes into permanent regressions during remediation; temporary files are not a release gate.

## Required findings

Severity below is an engineering assessment of demonstrated behavior and its preconditions, not an assigned advisory score.

### S1 — High: single-use JWT replay records expire before token acceptance ends

Owners: `src/Token/Jwt/SymmetricJwt.php:136`, `src/Token/Jwt/AsymmetricJwt.php:144`, `src/Token/Jwt/JwtValidator.php` temporal validation; replay contract and documentation.

Both JWT verifiers accept tokens until `exp + leewaySeconds`, but `SINGLE_USE` passes only `exp` to `consume()`. With a store that expires records at the supplied timestamp, a token accepted once before `exp` is accepted again during leeway. This affects password-reset, email-verification and action JWT policies when used with expiring storage.

Reproduction: issue at time 1000 with `exp=1010`, verify once successfully, reject an immediate duplicate, advance to 1011. Both symmetric and EdDSA asymmetric verification accept the same token again with default 30-second leeway. The store received 1010 on every call. Existing test stores retain records indefinitely and miss this boundary.

Fix and acceptance:

- Retain single-use state through the full acceptance window, following the existing client-assertion implementation, which already consumes through `exp + leeway`.
- Calculate the retention deadline without integer overflow. Preserve the original claim expiry independently of retention; do not change `DENYLIST` record matching accidentally.
- Document required denylist retention through the configured acceptance window for host-owned revocation writers. Keep replay-store signatures compatible.
- Add expiring-store tests for both JWT families, every single-use policy, zero/nonzero leeway, before/at/after expiry, duplicate verification and overflow boundaries. Invalid signatures/claims must never consume state.

### S2 — Medium: DPoP replay retention misses the inclusive maximum-age boundary

Owner: `src/Token/Jwt/DpopProof.php:150`, `isAcceptedIssuedAt()` and replay tests.

DPoP accepts `iat == now - maximumAgeSeconds`, while consuming only through `iat + maximumAgeSeconds`. At that boundary the retention deadline is already `now`. A time-expiring store can immediately remove the record and accept another copy in the same second.

Reproduction: `iat=700`, `now=1000`, default maximum age 300. Two verifications of the same signed proof succeed; both consume calls receive expiry 1000.

Fix: keep the existing inclusive acceptance semantics and retain through the following second, with checked arithmetic, or explicitly justify a compatible protocol boundary correction. Cover oldest accepted proofs, future skew, second rollover, concurrent duplicates, `ath`/nonce bindings and expiring stores. No cryptographic, method/URI or replay check may be weakened.

### S3 — High, deployment-dependent: remote JOSE public-address policy accepts non-public destinations

Owners: `src/Token/Jwt/RemoteJwksConfiguration.php:74` and `src/Token/Jwt/Support/RemoteJoseResource.php:107`.

`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE` does not mean globally reachable unicast. The configured-literal path and outbound boundary both accept `100.64.0.1`, `198.18.0.1`, `192.0.2.1`, `224.0.0.1`, `2001:db8::1` and `ff02::1`. Each probe reached the mock HTTP client. A controlled DNS answer can expose the same gap for a trusted configured hostname; no real request to those destinations was made.

This is an incomplete SSRF defense, especially where non-public shared/benchmark space is routed internally. Token-supplied `jku`/`x5u` remains unused, and exploitability still depends on configuration, DNS and transport/egress behavior.

Fix and acceptance:

- Apply one consistent public-unicast policy to URL literals, every A/AAAA answer and IPv4-mapped IPv6 addresses. Reject mixed public/non-public answers before sending.
- Prefer supported native validation, including evaluation of `FILTER_FLAG_GLOBAL_RANGE`, plus explicit multicast checks. The local probe shows the global flag alone still accepts multicast; do not replace one incomplete predicate with another.
- Add exact-address and CIDR-boundary tests on PHP 8.4/8.5 for shared, benchmark, documentation, multicast, loopback, private, link-local, unspecified, reserved and mapped forms; include genuine public IPv4/IPv6 positives.
- Preserve HTTPS/host allowlists, repeat resolution, response bounds and visible-redirect rejection. Existing PSR-18 transport pinning, timeout, proxy and no-auto-redirect requirements remain host responsibilities.

Sources: [PHP validation flags](https://www.php.net/manual/en/filter.constants.validation.php), [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry/), [IANA IPv6 special-purpose registry](https://www.iana.org/assignments/iana-ipv6-special-registry/).

### S4 — Medium: undeclared Ctype dependency breaks production integrity and JOSE verification

Owners: `src/Integrity/StringHasher.php:59`, `src/Integrity/FileHasher.php:100`, `src/Token/Jwt/Support/JwtToken.php:135`, production smoke.

Composer does not require `ext-ctype`; the production dependency tree does not supply its polyfill. The development installation masks the dependency. With a clean `--no-dev` installation and `php -n` (all declared crypto extensions remain present), string/file integrity verification throws undefined-function errors and a correctly issued JWT fails verification. The same operations pass with Ctype enabled.

Prefer removing these incidental Ctype calls using precise native byte/regex checks, including JSON's actual whitespace grammar. Declaring a new hard extension would expand the deployment contract unnecessarily. Retain malformed-digest and duplicate-key rejection. Extend the production-only smoke to include integrity **verification** and an actual JWT issue/verify round trip under the declared minimal extension set.

### S5 — Medium: JWKS cache keys violate the PSR-16 interoperability contract

Owner: `src/Token/Jwt/RemoteJwks.php:40`; permissive cache fake in `tests/Token/Jwt/RemoteJwksTest.php`.

The key `epicrypt:jwks:` plus a 64-character digest contains reserved colons and is 78 bytes. A conforming cache rejects the reserved characters; a provider supporting only the required 64-byte key minimum cannot accept its length either. The strict-cache probe throws before any network request.

Use an ASCII-safe, at-most-64-character key, preferably a full SHA-256 hex digest over an explicitly domain-separated, versioned canonical identity. Update test fixtures and document the cold-cache transition. Add a strict PSR-16 provider/fake regression instead of relying solely on a permissive array cache.

Source: [PSR-16 key requirements](https://www.php-fig.org/psr/psr-16/).

### S6 — Medium: different JWKS trust/freshness policies share cache entries

Owner: `src/Token/Jwt/RemoteJwks.php:40`, `load()` and `cached()`.

The cache identity includes issuer and configured JWKS URI/discovery mode, but omits policy. A cache entry fetched with a 3,600-second TTL is reused without network access by another instance configured for a five-second maximum TTL and no stale allowance. Reproduction: populate at 1000, read through the strict instance at 1100; it returns the old key with zero HTTP requests.

Version the cache identity and include normalized settings that affect destination trust, freshness/stale behavior and accepted resource bounds. Alternatively, persist enough provenance to enforce the reader's policy; prefer the simpler complete-identity design. Keep equivalent allowlists order-independent. Resolver/transport deployments with materially different trust guarantees must also use separate caller-owned cache namespaces.

Cover same-policy hits; different TTL/stale/host/bound policies; discovery and explicit URI separation; malformed entries; no-cache/no-store; force refresh. Review cache exceptions and failed get/set/delete behavior explicitly: public metadata cache outages must not become stale authorization-state fallbacks. Preserve existing authoritative token-store failure behavior.

### S7 — Medium: remote response read loop has no no-progress guard

Owner: `src/Token/Jwt/Support/RemoteJoseResource.php:49`.

For a PSR-7 body returning `''` while `eof()` remains false, the loop never changes its byte count. The bounded probe returned empty strings until its fifth read deliberately threw; Epicrypt did not reject the stall. A persistent stalled stream can hold a worker indefinitely even though byte bounds are satisfied.

Reject no-progress reads with `KeyResolutionException`, preserving exact-limit success, oversized-response rejection and normal chunked reads. Cover unknown sizes, read exceptions, truncated bodies, empty reads with/without EOF and malformed JSON. Host connect/read/total timeouts remain necessary for blocking transport calls.

### Q1 — Required quality remediation: 20 complexity diagnostics and one Rector change

The current PHPForge version reports these valid complexity findings:

| Owner | Diagnostic |
| --- | --- |
| `OAuthAccessTokenService::validatedState()` | Function 13 |
| `OAuthClientAssertionValidator::validateClaims()` | Function 13 |
| `OAuthClientKeySet::__construct()` | Function 14 |
| `OAuthTokenEndpoint::refreshToken()` | Function 15 |
| `RefreshTokenManager::rotate()` | Function 13 |
| `OpenSslExtensionConfig::createTempConfig()` | Function 13 |
| `StreamIO::readChunk()` | Function 13 |
| `WrappedSecretManager::unwrapCandidateSet()` | Function 14 |
| `SignedUrl` / `normalizeQuery()` | Class 86 / function 13 |
| `SignedUrlOptions::__construct()` | Function 14 |
| `Jwks` | Class 94 |
| `Jws` | Class 84 |
| `JwtClaims::normalizeCustomClaims()` | Function 15 |
| `JwtValidator::validateCustomClaims()` | Function 13 |
| `OpenIdIdTokenValidator::validateAuthentication()` | Function 16 |
| `JwkOkpCodec::importPrivate()` | Function 13 |
| `JwkPrivateKeyCodec::validateShape()` | Function 13 |
| `JwsSignature::opensslKey()` | Function 13 |
| `JwtToken::rejectDuplicateObjectKeys()` | Function 15 |

Simplify guards/branching first; use private methods for cohesive steps. A class-level finding requires lower total class complexity or a genuinely distinct collaborator, not simply moving branches among private methods. Do not create a type for each claim, frame or validation condition. Preserve security regressions and public APIs while refactoring. Apply and review Rector's nullsafe/coalesce simplification in `JwtPolicy::acceptsType()` through the existing processor workflow.

### Q2 — Non-blocking maintenance: abandoned development dependency

`composer why doctrine/annotations` identifies `phpbench/phpbench 1.7.0 -> doctrine/annotations ^2.0`, obtained through PHPForge's development toolchain. Production is unaffected. The installed PHPForge auditor intentionally reports abandoned packages as non-blocking, while plain Composer audit exits 1.

Coordinate removal/upgrade in the shared PHPForge/PHPBench owner once a compatible supported solution exists. Do not edit vendor, fake a Composer replacement or weaken audit policy. Report this warning accurately while fixing the blocking application and quality findings.

## Optional Runwire 2.1.1 integration for 3.2.0

Implement after S1-S7 and Q1 are resolved, within the same 3.2.0 release candidate. Benefits are cancellation/deadline propagation, cooperative fairness during long stream processing and correct composition with already runtime-aware host transports/stores. Individual OpenSSL/Sodium/password-hashing calls remain synchronous; no throughput improvement is established by this audit.

### Smallest proposed contract

One optional `Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext` would accept the **passed** `RuntimeContext`, optional active `RequestContext`, and optional host task `CoroutineScope`. Its independent justification is borrowed-lifecycle validation plus cancellation/checkpoint policy reused by stream and remote-resource operations. Use the released Pathwise 4.2 borrowed-context implementation as a design reference; do not introduce a production Pathwise dependency or require its wrapper type.

Append an optional named `context` argument to the affected operation methods. Forward the same object through existing internal calls. Bind per operation; retain no request context in static state or shared long-lived services. Pure short scalar crypto/token operations need no runtime wrapper.

Proposed usage, not an existing API:

```php
$context = new RunwireExecutionContext($runtime, $request, $scope);
$protector->protectStream($input, $output, $key, $options, context: $context);
```

An intermediary library accepts and forwards that same context, or forwards the three raw Runwire objects into the Epicrypt context at its boundary. The flow is framework -> intermediary -> Epicrypt -> existing stream/resource owner, with no service lookup or runtime discovery.

### Scope and ownership

- Initial owners: `SecretStream`, `FileProtector`, `FileHasher`, `RemoteJwks` and its internal resource boundary. Reuse existing stream loops; keep optional checks absent from unbound hot paths beyond a nullable guard.
- Validate runtime PID, request/runtime identity, request completion, scope/task liveness and both request/scope cancellation sources. Reject invalid, completed, cancelled or stale borrowed objects. Validate at entry, safe checkpoints, after suspension and before publishing output.
- Check deadlines/cancellation without needing coroutine capability. Use `RUNWIRE_COROUTINES` plus a live host scope to select periodic `yieldNow()`; a capability flag by itself is insufficient.
- Keep regular-file I/O synchronous. Readiness waits are eligible only for suitable caller-owned nonblocking streams and actual scoped scheduler support. Do not silently change caller stream blocking mode.
- Preserve normal calls when Runwire is absent; preserve synchronous execution when no applicable capability/scope is supplied. An explicitly cancelled/invalid context must fail, not fall back.
- Never create/start/stop `Runtime` or `Server`, own workers/listeners/event loops, complete the request, close the host scope, drain unrelated tasks, or alter host hooks.
- Pass cancellation through existing crypto/error wrappers and remote stale-cache handling deliberately. Cancellation must not be converted into successful stale JWKS retrieval.
- Preserve file atomic publication and staging cleanup on cancellation. For caller-owned stream output, retain documented partial-write/publication responsibility. Cryptographic framing, authentication, final-tag and trailing-data rules remain unchanged.
- HTTP and persistence are already caller-injected boundaries. Share context with runtime-aware adapters explicitly when supported; do not assume PSR-18/PSR-16 provides asynchronous operations or mutate arbitrary adapters.
- Do not offload private keys/passwords to a process, build an internal pool, parallelize state transitions or add async contracts as part of this integration.
- Keep Runwire under `require-dev` at exact `2.1.1`, plus `suggest`; production use remains opt-in. Declare unsupported-version conflicts based on the validated compatibility contract. No mandatory runtime dependency.

### Integration acceptance

Test direct framework -> Epicrypt and framework -> intermediary -> Epicrypt forwarding with identical borrowed objects; runtime capability missing; scope missing; Runwire entirely absent; normal PHP-FPM; live native coroutine scope; cancelled/expired/completed/mismatched contexts; closed/wrong-task scope; fork/PID mismatch; request replacement; nested composition; interleaved tasks; cancelled file publication; and cancellation during remote fetch/cache refresh. Assert host workers, scope and request lifecycle remain usable and owned by the host.

Use one focused integration test file and existing suites unless a distinct backend needs separate fixtures. Test the exact released Runwire 2.1.1, not just sibling development HEAD. Add Swoole/OpenSwoole acceptance only for explicitly supported capability/transport paths.

## Pathwise 4.2 and bounded improvements

Pathwise is development-only; `^4.1` already permits 4.2, and existing stream/context containment tests pass with installed 4.2. Set the intended integration-test baseline to `^4.2` when implementing the next-release plan, update test descriptions and remaining 4.1 guidance, and retain production smoke coverage with Pathwise absent. No core filesystem rewrite is necessary.

The 287-file inventory warrants a proportionate cohesion review, not blanket deletion. Keep public store interfaces, protocol records/results, policy enums, catchable exceptions and distinct crypto/security boundaries. Consolidate only demonstrated equivalent internal wrappers or redundant conversions while touching their owner. Broad public-type removals would need separate compatibility analysis and may require a major version; they are outside this 3.2.0 plan.

Review explicit password-cost policy documentation and runnable remote-resolver examples as documentation improvements. Preserve memory-hard defaults and host-owned rate limiting, durable storage, routing/consent UI and authorization policy.

## Execution order and release gates

1. Turn S1-S7 probes into permanent regressions in existing JWT/JOSE/integrity/production-smoke suites. Record failures on the old source.
2. Fix replay windows, destination policy and minimal-production behavior first, then cache interoperability/isolation and response progress. Keep each owner cohesive and preserve formats/public signatures.
3. Resolve Q1 with the configured sequential PHPForge processors, review every mutation, run focused tests and active static/refactor checks. Report Q2 separately.
4. Update security/storage/platform guidance with the fixes and retain one 3.2.0 release candidate.
5. Implement optional Runwire support and Pathwise 4.2 baseline/docs in that candidate; complete all integration acceptance cases.
6. Certify the complete final committed revision against every applicable gate, then prepare the single 3.2.0 release; report implementation, local validation, hosted validation and published tag/release separately.

Required final gates:

- [ ] Every S1-S7 regression fails before its fix and passes afterward; Q1 static/refactor gates are clean.
- [ ] `composer ic:process`, `composer ic:tests:details` and final `composer ic:release:guard`, following installed PHPForge agent workflow. No gate weakening or vendor edits.
- [ ] Supported PHP 8.4/8.5 and lowest/current supported dependencies validate the final revision; record deprecation and platform differences.
- [ ] Fresh production-only installation exercises valid/invalid integrity and JWT/JOSE paths without dev packages, Pathwise or Runwire, using only declared required extensions.
- [ ] Strict Sphinx build, runnable affected examples, independent Node JOSE/OAuth interoperability and npm audit pass.
- [ ] Existing Windows publication, AEGIS-positive and mutation-floor lanes pass on the final SHA; preserve skip policy and all existing thresholds.
- [ ] Authentication benchmark and PHPBench affected paths pass with matching runtime/dependency/OPcache metadata. Existing 2 MiB repeated-PAT heap guard remains active.
- [ ] For Runwire or material request-path changes, measure repeated production-equivalent PHP-FPM and supported persistent-host scenarios, including unbound/bound calls, stream work, cancellation and remote hit/miss paths. Record correctness, successful RPM, latency, errors/timeouts and live process-tree memory. Apply the engineering-principles default 2% median successful-RPM regression budget only on matched stable environments; current microbenchmarks cannot certify it.
- [ ] Focused persistent-host repetition covers context reset, tenant/request isolation, failures, worker replacement and bounded memory/resource growth. Reuse existing harnesses; avoid duplicative long soak infrastructure without a workload need.
- [ ] A fresh exact-SHA hosted run validates the candidate after code/dependency/workflow changes. Historical green runs are supporting baseline evidence only.
- [ ] Release notes explain security acceptance changes, cache cold-start/namespace transition, supported PHP/Pathwise/Runwire contracts and remaining host responsibilities. No tag until all applicable blocking gates are closed.

Completion means confirmed defects are fixed and their regressions/gates pass. A green baseline suite or zero Composer advisories does not close these findings.
