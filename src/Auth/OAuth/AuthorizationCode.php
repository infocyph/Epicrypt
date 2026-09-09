<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Psr\Clock\ClockInterface;

final readonly class AuthorizationCode
{
    public const int DEFAULT_LIFETIME_SECONDS = 300;

    public const int MAXIMUM_LIFETIME_SECONDS = 600;

    private const string TOKEN_USE = 'authorization_code';

    /** @var list<string> */
    public array $authenticationMethods;

    /** @var list<string> */
    public array $audiences;

    /** @var list<string> */
    public array $scopes;

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $authenticationMethods
     */
    public function __construct(
        public string $issuer,
        public string $codeId,
        public string $authorizationId,
        public string $subject,
        public string $clientId,
        public string $redirectUriHash,
        public string $pkceChallenge,
        array $scopes,
        array $audiences,
        public int $issuedAt,
        public int $expiresAt,
        public ?string $nonce = null,
        public ?int $authenticationTime = null,
        public ?string $authenticationContext = null,
        array $authenticationMethods = [],
    ) {
        self::assertIdentifier($this->issuer, 2048, 'Authorization-code issuer');
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->codeId) !== 1) {
            throw new ConfigurationException('Authorization-code ID must be a 192-bit Base64URL value.');
        }
        self::assertIdentifier($this->authorizationId, 255, 'Authorization ID');
        self::assertIdentifier($this->subject, 255, 'Authorization-code subject');
        self::assertIdentifier($this->clientId, 255, 'Authorization-code client ID');
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->redirectUriHash) !== 1) {
            throw new ConfigurationException('Authorization-code redirect URI hash must be a SHA-256 Base64URL value.');
        }
        if (preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $this->pkceChallenge) !== 1) {
            throw new ConfigurationException('Authorization-code PKCE challenge must be an S256 Base64URL value.');
        }
        $this->scopes = self::normalizeScopes($scopes);
        $this->audiences = self::normalizeAudiences($audiences);
        if ($this->issuedAt < 1
            || $this->issuedAt >= $this->expiresAt
            || ($this->expiresAt - $this->issuedAt) > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('Authorization-code lifetime must be positive and no longer than 600 seconds.');
        }
        if ($this->nonce !== null) {
            self::assertIdentifier($this->nonce, 256, 'Authorization-code OIDC nonce');
        }
        if ($this->authenticationTime !== null
            && ($this->authenticationTime < 1 || $this->authenticationTime > $this->issuedAt)) {
            throw new ConfigurationException('Authorization-code authentication time must not be after issuance.');
        }
        if ($this->authenticationContext !== null) {
            self::assertIdentifier($this->authenticationContext, 255, 'Authorization-code authentication context');
        }
        $this->authenticationMethods = self::normalizeAuthenticationMethods($authenticationMethods);
        if (($this->nonce !== null
                || $this->authenticationTime !== null
                || $this->authenticationContext !== null
                || $this->authenticationMethods !== [])
            && !in_array('openid', $this->scopes, true)) {
            throw new ConfigurationException('Authorization-code OIDC transaction state requires the openid scope.');
        }
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @param array<array-key, mixed> $audiences
     * @param array<array-key, mixed> $authenticationMethods
     */
    public static function issue(
        string $issuer,
        string $authorizationId,
        string $subject,
        string $clientId,
        string $redirectUri,
        string $pkceChallenge,
        array $scopes,
        array $audiences,
        int $lifetimeSeconds = self::DEFAULT_LIFETIME_SECONDS,
        ?string $nonce = null,
        ?int $authenticationTime = null,
        ?string $authenticationContext = null,
        array $authenticationMethods = [],
        ClockInterface $clock = new SystemClock(),
    ): self {
        if ($lifetimeSeconds < 1 || $lifetimeSeconds > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('Authorization-code lifetime must be between 1 and 600 seconds.');
        }
        self::assertRedirectUri($redirectUri);
        $now = $clock->now()->getTimestamp();

        return new self(
            issuer: $issuer,
            codeId: Base64Url::encode(random_bytes(24)),
            authorizationId: $authorizationId,
            subject: $subject,
            clientId: $clientId,
            redirectUriHash: self::redirectUriHash($redirectUri),
            pkceChallenge: $pkceChallenge,
            scopes: $scopes,
            audiences: $audiences,
            issuedAt: $now,
            expiresAt: $now + $lifetimeSeconds,
            nonce: $nonce,
            authenticationTime: $authenticationTime,
            authenticationContext: $authenticationContext,
            authenticationMethods: $authenticationMethods,
        );
    }

    public function matchesClient(string $clientId): bool
    {
        return self::validIdentifier($clientId, 255) && hash_equals($this->clientId, $clientId);
    }

    public function matchesPkceVerifier(#[\SensitiveParameter] string $verifier): bool
    {
        if (preg_match('/\A[A-Za-z0-9._~-]{43,128}\z/D', $verifier) !== 1) {
            return false;
        }

        return hash_equals($this->pkceChallenge, Base64Url::encode(hash('sha256', $verifier, true)));
    }

    public function matchesRedirectUri(string $redirectUri): bool
    {
        return self::validRedirectUri($redirectUri)
            && hash_equals($this->redirectUriHash, self::redirectUriHash($redirectUri));
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'iss' => $this->issuer,
            'jti' => $this->codeId,
            'authorization_id' => $this->authorizationId,
            'sub' => $this->subject,
            'client_id' => $this->clientId,
            'redirect_uri_hash' => $this->redirectUriHash,
            'code_challenge' => $this->pkceChallenge,
            'code_challenge_method' => 'S256',
            'scope' => implode(' ', $this->scopes),
            'aud' => $this->audiences,
            'iat' => $this->issuedAt,
            'exp' => $this->expiresAt,
            'token_use' => self::TOKEN_USE,
            ...($this->nonce === null ? [] : ['nonce' => $this->nonce]),
            ...($this->authenticationTime === null ? [] : ['auth_time' => $this->authenticationTime]),
            ...($this->authenticationContext === null ? [] : ['acr' => $this->authenticationContext]),
            ...($this->authenticationMethods === [] ? [] : ['amr' => $this->authenticationMethods]),
        ];
    }

    public static function validTokenUse(mixed $value): bool
    {
        return is_string($value) && hash_equals(self::TOKEN_USE, $value);
    }

    private static function assertIdentifier(string $value, int $maximumBytes, string $label): void
    {
        if (!self::validIdentifier($value, $maximumBytes)) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    private static function assertRedirectUri(string $redirectUri): void
    {
        if (!self::validRedirectUri($redirectUri)) {
            throw new ConfigurationException('Authorization-code redirect URI is invalid.');
        }
    }

    /**
     * @param array<array-key, mixed> $authenticationMethods
     * @return list<string>
     */
    private static function normalizeAuthenticationMethods(array $authenticationMethods): array
    {
        if (!array_is_list($authenticationMethods) || count($authenticationMethods) > 16) {
            throw new ConfigurationException('Authorization-code authentication methods must be a bounded list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($authenticationMethods as $method) {
            if (!is_string($method) || !self::validIdentifier($method, 64) || isset($seen[$method])) {
                throw new ConfigurationException('Authorization-code authentication methods must contain unique bounded strings.');
            }
            $seen[$method] = true;
            $normalized[] = $method;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $audiences
     * @return list<string>
     */
    private static function normalizeAudiences(array $audiences): array
    {
        if ($audiences === [] || !array_is_list($audiences) || count($audiences) > 32) {
            throw new ConfigurationException('Authorization-code audiences must be a non-empty bounded list.');
        }
        $seen = [];
        $normalized = [];
        foreach ($audiences as $audience) {
            if (!is_string($audience) || !self::validIdentifier($audience, 2048) || isset($seen[$audience])) {
                throw new ConfigurationException('Authorization-code audiences must contain unique bounded strings.');
            }
            $seen[$audience] = true;
            $normalized[] = $audience;
        }

        return $normalized;
    }

    /**
     * @param array<array-key, mixed> $scopes
     * @return list<string>
     */
    private static function normalizeScopes(array $scopes): array
    {
        if (!array_is_list($scopes) || count($scopes) > 64) {
            throw new ConfigurationException('Authorization-code scopes must be a bounded list.');
        }
        $seen = [];
        $normalized = [];
        $totalBytes = 0;
        foreach ($scopes as $scope) {
            if (!is_string($scope)
                || strlen($scope) > 255
                || preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+\z/D', $scope) !== 1
                || isset($seen[$scope])) {
                throw new ConfigurationException('Authorization-code scopes must contain unique OAuth scope tokens.');
            }
            $totalBytes += strlen($scope) + ($normalized === [] ? 0 : 1);
            if ($totalBytes > 4096) {
                throw new ConfigurationException('Authorization-code scope value is too large.');
            }
            $seen[$scope] = true;
            $normalized[] = $scope;
        }

        return $normalized;
    }

    private static function redirectUriHash(string $redirectUri): string
    {
        return Base64Url::encode(hash('sha256', $redirectUri, true));
    }

    private static function validIdentifier(string $value, int $maximumBytes): bool
    {
        return $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    private static function validRedirectUri(string $redirectUri): bool
    {
        return self::validIdentifier($redirectUri, 2048);
    }
}
