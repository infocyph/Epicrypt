<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Personal;

/**
 * Authoritative state for generic personal/API JWTs.
 *
 * Raw JWTs are never persisted. The unique token key is tokenId/jti. Reads used
 * for verification are security-sensitive: revocation must not be hidden by
 * stale cached active records.
 */
interface PersonalAccessTokenStoreInterface
{
    /** Return false only when tokenId already exists. */
    public function create(PersonalAccessTokenRecord $record): bool;

    public function find(string $tokenId): ?PersonalAccessTokenRecord;

    /**
     * Return at most $limit records for exactly one subject, newest createdAt
     * first with tokenId ascending as the deterministic tie-breaker. Implementations
     * must reject/avoid unbounded listing beyond the public hard ceiling.
     *
     * @return list<PersonalAccessTokenRecord>
     */
    public function listForSubject(string $subject, int $limit = 100): array;

    /**
     * Atomically revoke the first matching tokenId+subject and return current state.
     * Unknown/mismatched records return null; repeated revocation is idempotent.
     */
    public function revoke(string $tokenId, string $subject, int $revokedAt): ?PersonalAccessTokenRecord;

    /**
     * Revoke all currently active tokens for subject and return newly revoked count.
     *
     * create() and revokeAll() for the same subject need a serializable ordering:
     * tokens created after the serialized revoke-all point may remain active.
     */
    public function revokeAll(string $subject, int $revokedAt): int;
}
