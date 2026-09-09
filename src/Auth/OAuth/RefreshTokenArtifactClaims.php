<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class RefreshTokenArtifactClaims
{
    public const int MAXIMUM_ABSOLUTE_LIFETIME_SECONDS = 31_536_000;

    private const string TOKEN_USE = 'refresh_token';

    public function __construct(
        public string $issuer,
        public string $tokenId,
        public string $familyId,
        public RefreshTokenGrant $grant,
        public int $issuedAt,
        public int $idleExpiresAt,
    ) {
        self::assertIdentifier($this->issuer, 2048, 'Refresh-token issuer');
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->tokenId) !== 1) {
            throw new ConfigurationException('Refresh-token ID must be a 192-bit Base64URL value.');
        }
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->familyId) !== 1) {
            throw new ConfigurationException('Refresh-token family ID must be a 256-bit Base64URL value.');
        }
        if ($this->issuedAt < 1
            || $this->issuedAt >= $this->idleExpiresAt
            || $this->idleExpiresAt > $this->grant->expiresAt
            || ($this->grant->expiresAt - $this->issuedAt) > self::MAXIMUM_ABSOLUTE_LIFETIME_SECONDS) {
            throw new ConfigurationException('Refresh-token timestamps exceed the supported absolute or idle lifetime.');
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'iss' => $this->issuer,
            'jti' => $this->tokenId,
            'family_id' => $this->familyId,
            'authorization_id' => $this->grant->authorizationId,
            'sub' => $this->grant->subject,
            'client_id' => $this->grant->clientId,
            'aud' => $this->grant->audiences,
            'scope' => implode(' ', $this->grant->scopes),
            'iat' => $this->issuedAt,
            'exp' => $this->grant->expiresAt,
            'idle_exp' => $this->idleExpiresAt,
            'token_use' => self::TOKEN_USE,
            ...($this->grant->dpopKeyThumbprint === null ? [] : ['dpop_jkt' => $this->grant->dpopKeyThumbprint]),
        ];
    }

    public static function validTokenUse(mixed $value): bool
    {
        return is_string($value) && hash_equals(self::TOKEN_USE, $value);
    }

    private static function assertIdentifier(string $value, int $maximumBytes, string $label): void
    {
        if ($value === '' || strlen($value) > $maximumBytes || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }
}
