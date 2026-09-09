<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweContentEncryptionAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Cryptographic refresh-token profile only. A successfully decrypted artifact is
 * not active until the authoritative refresh-family store accepts its token/family state.
 */
final readonly class RefreshTokenArtifact
{
    public const int DEFAULT_IDLE_LIFETIME_SECONDS = 2_592_000;

    public const int MAXIMUM_IDLE_LIFETIME_SECONDS = 31_536_000;

    private const int MAXIMUM_FUTURE_SKEW_SECONDS = 30;

    public function __construct(
        private KeyRing $keys,
        private string $issuer,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($this->issuer === ''
            || strlen($this->issuer) > 2048
            || preg_match('/[\x00-\x1F\x7F]/', $this->issuer) === 1) {
            throw new ConfigurationException('Refresh-token artifact issuer is invalid.');
        }
    }

    public function issue(
        RefreshTokenGrant $grant,
        ?string $familyId = null,
        int $idleLifetimeSeconds = self::DEFAULT_IDLE_LIFETIME_SECONDS,
    ): RefreshTokenArtifactIssue {
        self::assertIdleLifetime($idleLifetimeSeconds);
        $now = $this->clock->now()->getTimestamp();
        if ($grant->expiresAt <= $now
            || ($grant->expiresAt - $now) > RefreshTokenArtifactClaims::MAXIMUM_ABSOLUTE_LIFETIME_SECONDS) {
            throw new ConfigurationException('Refresh-token grant expiration is outside the supported lifetime.');
        }
        $familyId ??= Base64Url::encode(random_bytes(32));
        $claims = new RefreshTokenArtifactClaims(
            issuer: $this->issuer,
            tokenId: Base64Url::encode(random_bytes(24)),
            familyId: $familyId,
            grant: $grant,
            issuedAt: $now,
            idleExpiresAt: min($grant->expiresAt, $now + $idleLifetimeSeconds),
        );
        $entry = $this->keys->activeForWrite(
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            $this->issuer,
        );
        $token = new Jwe(
            $entry->key,
            JweKeyManagementAlgorithm::DIRECT,
            JweContentEncryptionAlgorithm::A256GCM,
            $entry->id,
        )->encryptCompact(
            Json::encode($claims->toArray()),
            ['typ' => AuthTokenClass::OAUTH_REFRESH_TOKEN->joseType()],
        );

        return new RefreshTokenArtifactIssue($token, $claims);
    }

    public function decrypt(#[\SensitiveParameter] string $token): RefreshTokenArtifactClaims
    {
        [$keyId, $header] = $this->protectedHeader($token);
        $this->validateProtectedHeader($header);
        $entry = $this->keys->resolveForRead(
            $keyId,
            KeyPurpose::OAUTH_REFRESH_TOKEN_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            $this->issuer,
        );
        if ($entry === null) {
            throw new InvalidTokenException('Refresh-token protection key is unavailable.');
        }

        try {
            $plaintext = new Jwe(
                $entry->key,
                JweKeyManagementAlgorithm::DIRECT,
                JweContentEncryptionAlgorithm::A256GCM,
                $entry->id,
            )->decryptCompact($token);
            $claims = Json::decodeToArray($plaintext);
        } catch (InvalidTokenException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new InvalidTokenException('Refresh-token artifact payload is invalid.', 0, $exception);
        }

        $artifact = $this->claimsFromPayload($claims);
        $now = $this->clock->now()->getTimestamp();
        if (!hash_equals($this->issuer, $artifact->issuer)
            || $artifact->issuedAt > ($now + self::MAXIMUM_FUTURE_SKEW_SECONDS)
            || $now >= $artifact->idleExpiresAt
            || $now >= $artifact->grant->expiresAt) {
            throw new InvalidTokenException('Refresh-token artifact is outside its valid issuer or time window.');
        }

        return $artifact;
    }

    /** @param array<string, mixed> $claims */
    private function claimsFromPayload(array $claims): RefreshTokenArtifactClaims
    {
        $allowed = [
            'iss' => true,
            'jti' => true,
            'family_id' => true,
            'grant_id' => true,
            'sub' => true,
            'client_id' => true,
            'aud' => true,
            'scope' => true,
            'iat' => true,
            'exp' => true,
            'idle_exp' => true,
            'token_use' => true,
            'dpop_jkt' => true,
        ];
        if (array_diff_key($claims, $allowed) !== []) {
            throw new InvalidTokenException('Refresh-token artifact contains unsupported claims.');
        }
        foreach (['iss', 'jti', 'family_id', 'grant_id', 'sub', 'client_id', 'aud', 'scope', 'iat', 'exp', 'idle_exp', 'token_use'] as $claim) {
            if (!array_key_exists($claim, $claims)) {
                throw new InvalidTokenException(sprintf('Refresh-token artifact is missing %s.', $claim));
            }
        }
        if (!RefreshTokenArtifactClaims::validTokenUse($claims['token_use'] ?? null)
            || !is_array($claims['aud'])
            || !is_string($claims['scope'])
            || !is_int($claims['iat'])
            || !is_int($claims['exp'])
            || !is_int($claims['idle_exp'])) {
            throw new InvalidTokenException('Refresh-token artifact claim profile is invalid.');
        }
        $scopes = $claims['scope'] === '' ? [] : explode(' ', $claims['scope']);

        try {
            $grant = new RefreshTokenGrant(
                id: self::stringClaim($claims, 'grant_id'),
                subject: self::stringClaim($claims, 'sub'),
                clientId: self::stringClaim($claims, 'client_id'),
                audiences: $claims['aud'],
                scopes: $scopes,
                expiresAt: $claims['exp'],
                dpopKeyThumbprint: self::nullableStringClaim($claims, 'dpop_jkt'),
            );

            return new RefreshTokenArtifactClaims(
                issuer: self::stringClaim($claims, 'iss'),
                tokenId: self::stringClaim($claims, 'jti'),
                familyId: self::stringClaim($claims, 'family_id'),
                grant: $grant,
                issuedAt: $claims['iat'],
                idleExpiresAt: $claims['idle_exp'],
            );
        } catch (ConfigurationException $exception) {
            throw new InvalidTokenException('Refresh-token artifact claims are invalid.', 0, $exception);
        }
    }

    /** @return array{string, array<string, mixed>} */
    private function protectedHeader(#[\SensitiveParameter] string $token): array
    {
        JosePolicy::assertInputSize($token, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Refresh-token artifact');
        $parts = explode('.', $token);
        if (count($parts) !== 5 || $parts[0] === '') {
            throw new InvalidTokenException('Refresh-token artifact must use compact JWE serialization.');
        }

        try {
            $header = Json::decodeToArray(Base64Url::decode($parts[0]));
        } catch (Throwable $exception) {
            throw new InvalidTokenException('Refresh-token protected header is invalid.', 0, $exception);
        }
        $keyId = $header['kid'] ?? null;
        if (!is_string($keyId) || !JosePolicy::isKeyId($keyId)) {
            throw new InvalidTokenException('Refresh-token protected header requires a valid kid.');
        }

        return [$keyId, $header];
    }

    /** @param array<string, mixed> $header */
    private function validateProtectedHeader(array $header): void
    {
        if (count($header) !== 4
            || ($header['alg'] ?? null) !== JweKeyManagementAlgorithm::DIRECT->value
            || ($header['enc'] ?? null) !== JweContentEncryptionAlgorithm::A256GCM->value
            || !is_string($header['typ'] ?? null)
            || !AuthTokenClass::OAUTH_REFRESH_TOKEN->acceptsJoseType($header['typ'])) {
            throw new InvalidTokenException('Refresh-token protected header profile is invalid.');
        }
    }

    private static function assertIdleLifetime(int $idleLifetimeSeconds): void
    {
        if ($idleLifetimeSeconds < 1 || $idleLifetimeSeconds > self::MAXIMUM_IDLE_LIFETIME_SECONDS) {
            throw new ConfigurationException('Refresh-token idle lifetime must be between 1 second and 1 year.');
        }
    }

    /** @param array<string, mixed> $claims */
    private static function nullableStringClaim(array $claims, string $name): ?string
    {
        if (!array_key_exists($name, $claims)) {
            return null;
        }

        return is_string($claims[$name])
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Refresh-token %s claim must be a string.', $name));
    }

    /** @param array<string, mixed> $claims */
    private static function stringClaim(array $claims, string $name): string
    {
        return is_string($claims[$name] ?? null)
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Refresh-token %s claim must be a string.', $name));
    }
}
