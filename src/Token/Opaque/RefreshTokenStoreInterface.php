<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Opaque;

interface RefreshTokenStoreInterface
{
    /**
     * Persist a new active record. Return false only for a digest collision.
     */
    public function create(#[\SensitiveParameter] RefreshTokenRecord $record): bool;

    /**
     * Revoke the family resolved from any current or retained historical token digest.
     */
    public function revokeFamily(#[\SensitiveParameter] string $tokenDigest, int $revokedAt): bool;

    /**
     * Revoke every token belonging to the grant and return the affected family count.
     */
    public function revokeGrant(string $grantId, int $revokedAt): int;

    /**
     * Atomically validate, consume and replace one refresh token.
     *
     * The transaction must retain consumed records. Reuse of a consumed record must
     * revoke its complete family before returning REUSED. A successful rotation must
     * copy the original family and grant into a successor whose idle expiration is
     * min(grant expiration, now + idle lifetime). Binding mismatches must not consume
     * the token. Requested scopes must be equal to or narrower than the stored grant;
     * successful narrowing must be copied into the successor grant. CONFLICT is
     * reserved for a replacement-digest uniqueness collision.
     *
     * @param null|list<string> $requestedScopes
     * @return array{status: RefreshTokenRotationStatus, grant: RefreshTokenGrant|null}
     */
    public function rotate(
        #[\SensitiveParameter]
        string $currentDigest,
        #[\SensitiveParameter]
        string $replacementDigest,
        string $clientId,
        ?string $dpopKeyThumbprint,
        ?array $requestedScopes,
        int $now,
        int $idleLifetimeSeconds,
    ): array;
}
