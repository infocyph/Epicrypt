<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

/**
 * Optional authoritative status layer for RFC 9068 access JWTs.
 *
 * Deployments that select stateful/immediate access-token revocation create a
 * status record at issue time. Raw JWTs are never persisted by this contract.
 * The unique key is (issuer, tokenId). Revocation reads are security-sensitive.
 */
interface OAuthAccessTokenStatusStoreInterface
{
    /** Return false only when the issuer/tokenId pair already exists. */
    public function create(OAuthAccessTokenStatusRecord $record): bool;

    public function find(string $issuer, string $tokenId): ?OAuthAccessTokenStatusRecord;

    /**
     * Atomically record first revocation and return current state.
     * Unknown tokens return null; repeated revocation is idempotent.
     */
    public function revoke(string $issuer, string $tokenId, int $revokedAt): ?OAuthAccessTokenStatusRecord;
}
