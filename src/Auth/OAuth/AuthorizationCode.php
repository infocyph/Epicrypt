<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
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
        AuthProtocolPolicy::assertText($this->issuer, AuthProtocolPolicy::MAX_ISSUER_BYTES, 'Authorization-code issuer');
        if (preg_match('/\A[A-Za-z0-9_-]{32}\z/D', $this->codeId) !== 1) {
            throw new ConfigurationException('Authorization-code ID must be a 192-bit Base64URL value.');
        }
        AuthProtocolPolicy::assertText($this->authorizationId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Authorization ID');
        AuthProtocolPolicy::assertText($this->subject, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Authorization-code subject');
        AuthProtocolPolicy::assertText($this->clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Authorization-code client ID');
        if (!AuthProtocolPolicy::validSha256Base64Url($this->redirectUriHash)) {
            throw new ConfigurationException('Authorization-code redirect URI hash must be a SHA-256 Base64URL value.');
        }
        if (!AuthProtocolPolicy::validSha256Base64Url($this->pkceChallenge)) {
            throw new ConfigurationException('Authorization-code PKCE challenge must be an S256 Base64URL value.');
        }
        $this->scopes = AuthProtocolPolicy::normalizeScopes($scopes, 'Authorization-code scopes');
        $this->audiences = AuthProtocolPolicy::normalizeAudiences($audiences, 'Authorization-code audiences');
        if ($this->issuedAt < 1
            || $this->issuedAt >= $this->expiresAt
            || ($this->expiresAt - $this->issuedAt) > self::MAXIMUM_LIFETIME_SECONDS) {
            throw new ConfigurationException('Authorization-code lifetime must be positive and no longer than 600 seconds.');
        }
        if ($this->nonce !== null) {
            AuthProtocolPolicy::assertText($this->nonce, AuthProtocolPolicy::MAX_NONCE_BYTES, 'Authorization-code OIDC nonce');
        }
        if ($this->authenticationTime !== null
            && ($this->authenticationTime < 1 || $this->authenticationTime > $this->issuedAt)) {
            throw new ConfigurationException('Authorization-code authentication time must not be after issuance.');
        }
        if ($this->authenticationContext !== null) {
            AuthProtocolPolicy::assertText($this->authenticationContext, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES, 'Authorization-code authentication context');
        }
        $this->authenticationMethods = AuthProtocolPolicy::normalizeAuthenticationMethods(
            $authenticationMethods,
            'Authorization-code authentication methods',
        );
        if ($this->nonce !== null && !in_array('openid', $this->scopes, true)) {
            throw new ConfigurationException('Authorization-code OIDC nonce requires the openid scope.');
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
        AuthProtocolPolicy::assertText($redirectUri, AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES, 'Authorization-code redirect URI');
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
        return AuthProtocolPolicy::validText($clientId, AuthProtocolPolicy::MAX_IDENTIFIER_BYTES)
            && hash_equals($this->clientId, $clientId);
    }

    public function matchesPkceVerifier(#[\SensitiveParameter] string $verifier): bool
    {
        return AuthProtocolPolicy::validPkceVerifier($verifier)
            && hash_equals($this->pkceChallenge, Base64Url::encode(hash('sha256', $verifier, true)));
    }

    public function matchesRedirectUri(string $redirectUri): bool
    {
        return AuthProtocolPolicy::validText($redirectUri, AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES)
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

    private static function redirectUriHash(string $redirectUri): string
    {
        return Base64Url::encode(hash('sha256', $redirectUri, true));
    }
}
