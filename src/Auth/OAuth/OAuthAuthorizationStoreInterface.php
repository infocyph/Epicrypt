<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

/**
 * Authoritative approved-authorization state.
 *
 * Raw authorization codes, access tokens and refresh tokens do not belong in
 * this store. Reads are security-sensitive: after revoke() commits, an adapter
 * must not continue returning a stale active record from an ordinary cache.
 */
interface OAuthAuthorizationStoreInterface
{
    /** Return false only when authorizationId already exists. */
    public function create(OAuthAuthorizationRecord $record): bool;

    public function find(string $authorizationId): ?OAuthAuthorizationRecord;

    /**
     * Atomically record first revocation and return current state.
     *
     * Unknown authorization IDs return null. Repeating revocation is idempotent
     * and returns the already-revoked record without changing revokedAt.
     */
    public function revoke(string $authorizationId, int $revokedAt): ?OAuthAuthorizationRecord;
}
