<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

/**
 * Authoritative read contract for OAuth protocol client registration data.
 *
 * Implementations MUST use exact, case-sensitive client-id identity with no
 * aliases or normalization. Returned records are immutable protocol snapshots;
 * administration/CRUD is intentionally outside Epicrypt's runtime contract.
 * Disabled registrations SHOULD still be returned with enabled=false so the
 * protocol core can apply one uniform invalid-client policy.
 *
 * Stale reads are security-sensitive for disablement, credential/key rotation,
 * redirect URIs, grants, scopes, audiences and authentication methods.
 */
interface OAuthClientStoreInterface
{
    public function find(string $clientId): ?OAuthClient;
}
