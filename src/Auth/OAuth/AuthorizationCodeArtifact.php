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
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class AuthorizationCodeArtifact
{
    private const int MAXIMUM_FUTURE_SKEW_SECONDS = 30;

    public function __construct(
        private KeyRing $keys,
        private string $issuer,
        private ClockInterface $clock = new SystemClock(),
    ) {
        if ($this->issuer === ''
            || strlen($this->issuer) > 2048
            || preg_match('/[\x00-\x1F\x7F]/', $this->issuer) === 1) {
            throw new ConfigurationException('Authorization-code artifact issuer is invalid.');
        }
    }

    public function decrypt(#[\SensitiveParameter] string $token): AuthorizationCode
    {
        [$keyId, $header] = $this->protectedHeader($token);
        $this->validateProtectedHeader($header);
        $entry = $this->keys->resolveForRead(
            $keyId,
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            $this->issuer,
        );
        if ($entry === null) {
            throw new InvalidTokenException('Authorization-code protection key is unavailable.');
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
            throw new InvalidTokenException('Authorization-code artifact payload is invalid.', 0, $exception);
        }

        $code = $this->codeFromClaims($claims);
        $now = $this->clock->now()->getTimestamp();
        if (!hash_equals($this->issuer, $code->issuer)
            || $code->issuedAt > ($now + self::MAXIMUM_FUTURE_SKEW_SECONDS)
            || $now >= $code->expiresAt) {
            throw new InvalidTokenException('Authorization-code artifact is outside its valid issuer or time window.');
        }

        return $code;
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $authenticationMethods
     */
    public function issue(
        string $authorizationId,
        string $subject,
        string $clientId,
        string $redirectUri,
        string $pkceChallenge,
        array $scopes,
        array $audiences,
        int $lifetimeSeconds = AuthorizationCode::DEFAULT_LIFETIME_SECONDS,
        ?string $nonce = null,
        ?int $authenticationTime = null,
        ?string $authenticationContext = null,
        array $authenticationMethods = [],
    ): AuthorizationCodeIssue {
        $code = AuthorizationCode::issue(
            issuer: $this->issuer,
            authorizationId: $authorizationId,
            subject: $subject,
            clientId: $clientId,
            redirectUri: $redirectUri,
            pkceChallenge: $pkceChallenge,
            scopes: $scopes,
            audiences: $audiences,
            lifetimeSeconds: $lifetimeSeconds,
            nonce: $nonce,
            authenticationTime: $authenticationTime,
            authenticationContext: $authenticationContext,
            authenticationMethods: $authenticationMethods,
            clock: $this->clock,
        );
        $entry = $this->keys->activeForWrite(
            KeyPurpose::OAUTH_AUTHORIZATION_CODE_PROTECTION,
            JweKeyManagementAlgorithm::DIRECT->value,
            $this->issuer,
        );
        $token = new Jwe(
            $entry->key,
            JweKeyManagementAlgorithm::DIRECT,
            JweContentEncryptionAlgorithm::A256GCM,
            $entry->id,
        )->encryptCompact(
            Json::encode($code->toArray()),
            ['typ' => AuthTokenClass::OAUTH_AUTHORIZATION_CODE->joseType()],
        );

        return new AuthorizationCodeIssue($token, $code);
    }

    /** @param array<string, mixed> $claims */
    private static function nullableIntClaim(array $claims, string $name): ?int
    {
        if (!array_key_exists($name, $claims)) {
            return null;
        }

        return is_int($claims[$name])
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Authorization-code %s claim must be an integer.', $name));
    }

    /** @param array<string, mixed> $claims */
    private static function nullableStringClaim(array $claims, string $name): ?string
    {
        if (!array_key_exists($name, $claims)) {
            return null;
        }

        return is_string($claims[$name])
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Authorization-code %s claim must be a string.', $name));
    }

    /**
     * @param array<string, mixed> $claims
     * @return array<array-key, mixed>
     */
    private static function optionalListClaim(array $claims, string $name): array
    {
        if (!array_key_exists($name, $claims)) {
            return [];
        }

        return is_array($claims[$name]) && array_is_list($claims[$name])
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Authorization-code %s claim must be a list.', $name));
    }

    /** @param array<string, mixed> $claims */
    private static function stringClaim(array $claims, string $name): string
    {
        return is_string($claims[$name] ?? null)
            ? $claims[$name]
            : throw new InvalidTokenException(sprintf('Authorization-code %s claim must be a string.', $name));
    }

    /** @param array<string, mixed> $claims */
    private function codeFromClaims(array $claims): AuthorizationCode
    {
        $allowed = [
            'iss' => true,
            'jti' => true,
            'authorization_id' => true,
            'sub' => true,
            'client_id' => true,
            'redirect_uri_hash' => true,
            'code_challenge' => true,
            'code_challenge_method' => true,
            'scope' => true,
            'aud' => true,
            'iat' => true,
            'exp' => true,
            'token_use' => true,
            'nonce' => true,
            'auth_time' => true,
            'acr' => true,
            'amr' => true,
        ];
        if (array_diff_key($claims, $allowed) !== []) {
            throw new InvalidTokenException('Authorization-code artifact contains unsupported claims.');
        }
        foreach (['iss', 'jti', 'authorization_id', 'sub', 'client_id', 'redirect_uri_hash', 'code_challenge', 'code_challenge_method', 'scope', 'aud', 'iat', 'exp', 'token_use'] as $claim) {
            if (!array_key_exists($claim, $claims)) {
                throw new InvalidTokenException(sprintf('Authorization-code artifact is missing %s.', $claim));
            }
        }
        if (($claims['code_challenge_method'] ?? null) !== 'S256' || !AuthorizationCode::validTokenUse($claims['token_use'] ?? null)) {
            throw new InvalidTokenException('Authorization-code artifact profile markers are invalid.');
        }
        if (!is_string($claims['scope'])
            || !is_array($claims['aud'])
            || !is_int($claims['iat'])
            || !is_int($claims['exp'])) {
            throw new InvalidTokenException('Authorization-code artifact claim types are invalid.');
        }

        $scopes = $claims['scope'] === '' ? [] : explode(' ', $claims['scope']);

        try {
            return new AuthorizationCode(
                issuer: self::stringClaim($claims, 'iss'),
                codeId: self::stringClaim($claims, 'jti'),
                authorizationId: self::stringClaim($claims, 'authorization_id'),
                subject: self::stringClaim($claims, 'sub'),
                clientId: self::stringClaim($claims, 'client_id'),
                redirectUriHash: self::stringClaim($claims, 'redirect_uri_hash'),
                pkceChallenge: self::stringClaim($claims, 'code_challenge'),
                scopes: $scopes,
                audiences: $claims['aud'],
                issuedAt: $claims['iat'],
                expiresAt: $claims['exp'],
                nonce: self::nullableStringClaim($claims, 'nonce'),
                authenticationTime: self::nullableIntClaim($claims, 'auth_time'),
                authenticationContext: self::nullableStringClaim($claims, 'acr'),
                authenticationMethods: self::optionalListClaim($claims, 'amr'),
            );
        } catch (ConfigurationException $exception) {
            throw new InvalidTokenException('Authorization-code artifact claims are invalid.', 0, $exception);
        }
    }

    /** @return array{string, array<string, mixed>} */
    private function protectedHeader(#[\SensitiveParameter] string $token): array
    {
        JosePolicy::assertInputSize($token, JosePolicy::MAX_COMPACT_TOKEN_BYTES, 'Authorization-code artifact');
        $parts = explode('.', $token);
        if (count($parts) !== 5 || $parts[0] === '') {
            throw new InvalidTokenException('Authorization-code artifact must use compact JWE serialization.');
        }

        try {
            $header = Json::decodeToArray(Base64Url::decode($parts[0]));
        } catch (Throwable $exception) {
            throw new InvalidTokenException('Authorization-code protected header is invalid.', 0, $exception);
        }
        $keyId = $header['kid'] ?? null;
        if (!is_string($keyId) || !JosePolicy::isKeyId($keyId)) {
            throw new InvalidTokenException('Authorization-code protected header requires a valid kid.');
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
            || !AuthTokenClass::OAUTH_AUTHORIZATION_CODE->acceptsJoseType($header['typ'])) {
            throw new InvalidTokenException('Authorization-code protected header profile is invalid.');
        }
    }
}
