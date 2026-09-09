<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

interface RefreshTokenStoreInterface
{
    /**
     * Persist one new active refresh-token family record.
     *
     * Return false only for a token-id or new-family-id uniqueness conflict.
     * Raw JWE values are never stored.
     */
    public function create(#[\SensitiveParameter] RefreshTokenRecord $record): bool;

    /**
     * Read authoritative refresh state without consuming or rotating it.
     *
     * Implementations must compare the supplied authenticated record to persisted
     * state exactly. Consumed/revoked/expired state is returned without mutation;
     * reuse-family revocation remains a rotate() responsibility.
     */
    public function inspect(
        #[\SensitiveParameter]
        RefreshTokenRecord $record,
        int $now,
    ): RefreshTokenInspectionStatus;

    /** Revoke every family belonging to an authorization and return affected family count. */
    public function revokeAuthorization(string $authorizationId, int $revokedAt): int;

    /** Revoke the family resolved from any current or retained historical token id. */
    public function revokeFamily(string $tokenId, int $revokedAt): bool;

    /**
     * Atomically validate, consume and replace one refresh token.
     *
     * The implementation must locate the authoritative record by current.tokenId and
     * verify the persisted state exactly matches current before any mutation. Consumed
     * records must be retained through the authorization lifetime; reuse of a consumed
     * record revokes its complete family before returning REUSED. Family revocation and
     * consumed-token reuse detection take precedence over idle expiration.
     *
     * Client/sender mismatches must not consume the token. On ROTATED, persist the exact
     * replacement record supplied here in the same atomic operation that marks current
     * consumed. replacement must preserve family, authorization, subject, client,
     * audiences, absolute expiration and sender binding; scopes may only narrow.
     *
     * A replacement token-id collision returns CONFLICT without consuming current.
     * Stale reads are security-sensitive: distributed implementations require
     * linearizable or transactionally equivalent behavior for this operation and
     * family revocation.
     */
    public function rotate(
        #[\SensitiveParameter]
        RefreshTokenRecord $current,
        #[\SensitiveParameter]
        RefreshTokenRecord $replacement,
        string $clientId,
        ?string $dpopKeyThumbprint,
        int $now,
    ): RefreshTokenRotationStatus;
}
