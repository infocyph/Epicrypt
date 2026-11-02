# Epicrypt 3.3 audit and release plan

Updated 2026-11-03. Recommended release: **3.3.0**, for new optional Runwire 3
compatibility plus dependency and correctness fixes. No new public method or
persisted-format change is required. Version tags and publication remain
maintainer-owned.

## Rules and scope

Follow [PHPForge engineering principles](../../../vendor/infocyph/phpforge/resources/engineering-principles.md)
and its [agent workflow](../../../vendor/infocyph/phpforge/resources/AGENTS.md).
Keep fixes in their existing owners, preserve public contracts and host-owned
workers/event loops, and retain all detector scopes, limits and performance
budgets. Do not edit vendor sources or add suppressions.

Review source security, dependency declarations/advisories, crypto and
JOSE/OAuth/OIDC/password/file boundaries, Runwire and Pathwise integration,
tests, documentation, package contents, isolated consumers, performance and CI.
The [3.2 audit](epicrypt-next-release-audit-plan.md) is historical evidence.

## Findings and required work

| Finding | Resolution and acceptance |
| --- | --- |
| Dependency compatibility | Raise phpseclib to ^4.0.3, Pathwise to ^4.2.1 and optional Runwire to ^3.0; remove the Runwire conflict. Test cancellation, capability checks, task isolation, context forwarding and synchronous fallback. |
| Resolver cancellation incorrectly permits stale keys | Preserve Runwire cancellation before generic resolver error wrapping. Regression reproduced two failures for independently cancelled resolver requests, covering explicit JWKS and discovery; retain parent-cancellation controls. |
| JWS accepts EC keys for the wrong algorithm | Bind ES256/ES384/ES512 to P-256/P-384/P-521 per [RFC 7518 section 3.4](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4), matching the existing JWT boundary. Seven mismatched-curve cases failed before the fix; retain signer/verifier rejection and matching-curve round trips. This requires a misconfigured trusted key; it does not demonstrate forgery with a correctly configured key. |
| Generated data in Composer archive | The pre-fix archive contained 717 entries, including Graphify caches and a local .aws directory entry. Exclude graphify-out, phpforge and .aws; inspect a rebuilt archive and verify every tracked runtime source is present. No credential content was observed or inspected. |
| Release fixture still installs Runwire 2.1.1 | Install ^3.0 in the common production dependency set used by all comparison variants. Preserve matched dependencies and existing budgets. |
| Node interoperability toolchain | Pin Node 26.13.0 LTS, npm 12.2.1 and latest stable jose 6.2.15, regenerate the lockfile, audit and rerun both bidirectional interoperability profiles. |
| Hosted performance diagnosis | Unchanged 5b709ad passed every nonperformance lane but failed RPM twice: borrowed c8 at -2.255%, then unbound c1 at -2.951%. Retain raw trials and all limits. Add an independent identical-code control at c1 in both modes; it supplements all six candidate-versus-3.2 comparisons and does not replace them. |
| Development dependency abandonment | Live Composer audit reports zero advisories and abandoned doctrine/annotations through PHPForge/PHPBench. Report separately; shared-toolchain remediation belongs upstream. |
| Lowest-dependency PHP deprecations | Hosted run 41456525235 on 436e943 reproduced implicit-nullable deprecations in Nyholm PSR-7 1.8.0 and HTTP mock-client 1.6.0. Isolated PHP 8.4 lowest validation also reproduced the same defect in psr/http-factory 1.0. Raise these minimums to ^1.8.2, ^1.6.1 and ^1.1 respectively, retaining the upstream PHP compatibility fixes. Preserve E_ALL and failure on deprecation. |
| Release fixture retains historical 3.2 audit baselines | For the 3.3 candidate, compare both modes against published 3.2. On unchanged 5080fad, local historical 3.1 comparison first rejected 5.439% baseline spread; the identical retry measured -3.061% median RPM. A matched diagnostic against published 3.2 passed at -0.762%. Correct the release reference, retain explicit overrides for 3.1/1b034ec, resolve immutable commit IDs and rerun all six comparisons. Keep 2% RPM, 5% spread, 256 MiB RSS, durations and trial counts unchanged. This does not claim a source performance fix. |

## Validation record

- Baseline PHP 8.5.4, libsodium 1.0.18: **387 tests / 1,770 assertions**.
- PHPForge doctor healthy; resolved bundled configs include maximum-level
  PHPStan, Psalm taint analysis and cognitive-complexity limits 80/12.
- Requested dependencies resolved to Runwire 3.0, phpseclib 4.0.3 and Pathwise
  4.2.1. Composer lock is ignored by this library; installed versions are local
  evidence and consumers resolve the declared ranges.
- Focused Runwire/Pathwise integration after the fix: **35 tests / 92 assertions**.
- Final `composer ic:process`, `composer ic:tests:details` and
  `composer ic:release:guard` pass on PHP 8.5.4: **401 tests / 1,802 assertions**.
  Syntax, references, comments, duplicates, style, architecture, maximum-level
  PHPStan, Psalm taint analysis and Rector remain enabled. Existing clone
  diagnostics remain at 29 groups / 5.79%; this change adds none.
- Full PHP 8.4.26 Alpine suite passes: **401 tests / 1,815 assertions**.
  Linked libsodium 1.0.22 exercises both AEGIS algorithms; the dedicated
  mandatory AEGIS lane also passes **2 tests / 8 assertions**. The PHP 8.5 host
  uses libsodium 1.0.18 and exercises the unsupported-algorithm behavior.
- Strict Sphinx (`-W --keep-going`) passes. Independent bidirectional JOSE
  and OAuth/OIDC fixtures pass with Node 26.13.0 LTS, npm 12.2.1 and jose
  6.2.15 after the final JWS fix; clean npm install/audit reports zero vulnerabilities.
- Final Composer archive: **297 entries**, all **291 tracked runtime files**,
  no generated graphs, local configuration or development payloads. SHA-256:
  `1f3c00b6f3357db3fb940ff1ae14f6c6cf8e521b56ac905b596922bd37cb1ac6`
  for revision 5b709ad; follow-up tooling changes are excluded from the archive.
  An isolated production-only install passes core smoke with `php -n`
  (no Ctype, Runwire or Pathwise), platform checks and phpseclib RSA-PSS smoke.
- PHPBench quick suite: **43 subjects, zero failures/errors**. Final focused
  JOSE benchmark: **4 subjects, zero failures/errors**. Authentication evidence
  covers all seven configured operations and **zero retained heap growth**
  over 2,000 iterations. These are supporting measurements, not matched FPM
  regression certification or claims of improved throughput.
- A **300.08-second** PHP 8.5 borrowed-host soak passes **9,607,772 isolated
  requests**, **96,078 cancellation checks** and **20,000 discarded scoped
  bindings**. Retained heap growth is **6,744 bytes**; scoped growth is
  **4,656 bytes**, below the unchanged 2 MiB bounds. This is local heap evidence,
  not the matched FPM process-tree RSS/replacement gate.
- Benchmark/comparator shell syntax and positive/six-negative comparator
  probes pass. Workflow YAML parses; the existing JWS mutation shard now
  includes `JwsSignature`, retaining its **66%** floor.
- Corrected lowest dependencies pass the complete `composer ic:ci --prefer-lowest`
  suite on isolated PHP 8.4.26 and PHP 8.5.4, including deprecation enforcement.
  The source snapshot retains Git metadata and the same 389 first-party PHP files as CI.
- Hosted revision `5b709ad` passed all nonperformance checks, including all
  15 mutation shards, PHP 8.4/8.5 stable/lowest, Windows, AEGIS, documentation,
  minimal consumers and interoperability. It does not certify a later revision.
- Initial hosted revision `436e943` passed all 15 security mutation shards,
  including JWS **90.77%** and remote JOSE **93.58%**, plus Windows publication.
  Its lowest-dependency deprecations were corrected as described above; fresh
  final-head certification remains authoritative for the follow-up revision.

This is the local audit snapshot prepared on branch `patch/runwire-3`, based
on `8b1cdf370a8676e536db96b7bd0ae66347141512`. Subsequent release certification
is recorded in the pull request's checks and description, which must identify
the final committed head. No earlier hosted run certifies later changes.
Logs and fixtures from the local audit are under `/tmp/epicrypt-*`; the results
above preserve the relevant evidence independently of temporary files.

## Outstanding certification

- Run all configured workflows after committing the final candidate: stable
  and lowest dependencies on PHP 8.4/8.5, mutation shards, Windows publication,
  docs, interoperability and independent acceptance.
- Local PHP and available prepared PHP test images lack PCOV/Xdebug; mutation
  scores were not measured locally. The expanded JWS shard must meet the
  existing floor in the coverage-enabled CI lane. Direct parallel mutation
  runs use a mode-0700 private temporary directory for worker result files.
- Run `bash benchmarks/docker-host-acceptance.sh` on a stable Docker host with
  the profile in [the benchmark guide](../benchmarking.rst): all matched
  unbound/borrowed comparisons at concurrency 1/4/8, warmup, three trials,
  300-second soak, live process-tree RSS and real FPM worker replacement.
  Retain the **2% median RPM**, **5% trial spread** and **256 MiB RSS** limits.
  For this 3.3 release, both references default to published 3.2; historical
  3.2-audit references remain available through the documented overrides.
  All six local cases qualified on 5b709ad across retained batches, with
  median changes from -0.473% to +1.631%; noisy trials were rejected unchanged.
  The final borrowed batch also passed a 300.125-second Alpine soak with
  5,131,090 isolated requests, 7,928 bytes retained heap growth, live RSS
  sampling and a real FPM restart. Hosted RPM remains unresolved as above.
- The requested dependency minimums and Windows matrix passed on 5b709ad;
  the follow-up toolchain and control changes need exact-head hosted results.
- `doctrine/annotations` abandonment is a development-only upstream
  PHPBench/PHPForge maintenance item, not a production advisory.

## Release checklist

- [x] Reproduce resolver cancellation defect before the fix and retain regression coverage.
- [x] Reproduce JWS curve mismatch acceptance; retain mismatched and matching curve coverage.
- [x] Update dependency constraints, optional suggestion, fixture and maintained guides.
- [x] Run PHPForge processors, detailed QA and release guard on the final source.
- [x] Inspect Composer archive and pass an isolated --no-dev consumer smoke without Runwire/Pathwise/Ctype.
- [x] Build strict Sphinx docs and run independent JOSE/OAuth interoperability checks.
- [x] Run relevant component/authentication benchmarks and 300-second persistent-host soak.
- [ ] Certify matched Alpine FPM RPM/worker replacement with unchanged budgets.
- [ ] Run PHP 8.4/8.5 stable/lowest, AEGIS, Windows, mutation and all other configured CI lanes on the final committed revision.
- [ ] Maintainer merge, tag, publication and verification of tag-only release dispatch.

Optional improvements are not release blockers unless supported by a concrete
defect or measurement. No speculative API expansion, architecture rewrite or
performance claim is proposed.
