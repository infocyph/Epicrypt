<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Psr\Clock\ClockInterface;

final readonly class DpopProof
{
    private const int MAX_FUTURE_SKEW_SECONDS = 300;

    private const int MAX_IDENTIFIER_BYTES = 256;

    private const int MAX_PROOF_AGE_SECONDS = 3600;

    public function __construct(private ClockInterface $clock = new SystemClock()) {}

    /**
     * @param array<string, mixed> $publicJwk
     */
    public function issue(
        string $method,
        string $uri,
        #[\SensitiveParameter]
        string $privateKey,
        array $publicJwk,
        AsymmetricJwtAlgorithm $algorithm,
        #[\SensitiveParameter]
        ?string $accessToken = null,
        ?string $nonce = null,
        ?int $issuedAt = null,
        ?string $jwtId = null,
    ): string {
        $method = $this->normalizeMethod($method);
        $this->assertConfiguredPublicJwk($publicJwk);
        $this->assertOptionalIdentifier($nonce, 'DPoP nonce');
        $this->assertOptionalIdentifier($jwtId, 'DPoP jti');
        $claims = [
            'htm' => $method,
            'htu' => $this->normalizeUri($uri),
            'iat' => $issuedAt ?? $this->clock->now()->getTimestamp(),
            'jti' => $jwtId ?? Base64Url::encode(random_bytes(16)),
        ];
        if ($accessToken !== null) {
            $claims['ath'] = Base64Url::encode(hash('sha256', $accessToken, true));
        }
        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }

        return Jws::signer($privateKey, $algorithm)->signCompact(
            Json::encode($claims),
            ['typ' => 'dpop+jwt', 'jwk' => $publicJwk],
        );
    }

    /**
     * @param array<string, mixed> $accessTokenClaims
     * @param array<string, mixed> $publicJwk
     */
    public function validateAccessTokenBinding(array $accessTokenClaims, array $publicJwk): void
    {
        $cnf = $accessTokenClaims['cnf'] ?? null;
        if (!is_array($cnf) || !is_string($cnf['jkt'] ?? null)
            || !hash_equals(new Jwks()->thumbprint($publicJwk), $cnf['jkt'])) {
            throw new InvalidTokenException('Access token cnf.jkt does not match the DPoP key.');
        }
    }

    /** @return array<string, mixed> */
    public function verify(
        #[\SensitiveParameter]
        string $proof,
        string $method,
        string $uri,
        AsymmetricJwtAlgorithm $algorithm,
        JwtReplayStoreInterface $replayStore,
        #[\SensitiveParameter]
        ?string $accessToken = null,
        ?string $nonce = null,
        int $maximumAgeSeconds = 300,
        int $maximumFutureSkewSeconds = 5,
    ): array {
        return $this->verifyResult(
            $proof,
            $method,
            $uri,
            $algorithm,
            $replayStore,
            $accessToken,
            $nonce,
            $maximumAgeSeconds,
            $maximumFutureSkewSeconds,
        )['claims'];
    }

    /** @return array{claims: array<string, mixed>, publicJwk: array<string, mixed>, keyThumbprint: string} */
    public function verifyResult(
        #[\SensitiveParameter]
        string $proof,
        string $method,
        string $uri,
        AsymmetricJwtAlgorithm $algorithm,
        JwtReplayStoreInterface $replayStore,
        #[\SensitiveParameter]
        ?string $accessToken = null,
        ?string $nonce = null,
        int $maximumAgeSeconds = 300,
        int $maximumFutureSkewSeconds = 5,
    ): array {
        if (strlen($proof) > JwtToken::MAX_TOKEN_SIZE) {
            throw new InvalidTokenException('DPoP proof exceeds the maximum size.');
        }
        $this->assertTemporalPolicy($maximumAgeSeconds, $maximumFutureSkewSeconds);
        $method = $this->normalizeMethod($method);
        $this->assertOptionalIdentifier($nonce, 'DPoP nonce');
        [$header, $claims] = $this->parse($proof);
        if (($header['typ'] ?? null) !== 'dpop+jwt' || ($header['alg'] ?? null) !== $algorithm->value
            || !is_array($header['jwk'] ?? null)) {
            throw new InvalidTokenException('DPoP protected header is invalid.');
        }
        $jwk = $this->stringKeyArray($header['jwk']);
        $this->assertPublicJwk($jwk);
        $publicKey = $algorithm->isEdDsa()
            ? new Jwks()->importOkpPublicKey($jwk, 'EdDSA', 'Ed25519')
            : new Jwks()->importPublicKeyFromJwk($jwk, $algorithm);
        if (!Jws::verifier($publicKey, $algorithm)->verifyCompact($proof)) {
            throw new InvalidTokenException('DPoP signature is invalid.');
        }

        $current = $this->clock->now()->getTimestamp();
        $issuedAt = $claims['iat'] ?? null;
        $jwtId = $claims['jti'] ?? null;
        if (($claims['htm'] ?? null) !== $method || ($claims['htu'] ?? null) !== $this->normalizeUri($uri)
            || !is_int($issuedAt) || !$this->isAcceptedIssuedAt($issuedAt, $current, $maximumAgeSeconds, $maximumFutureSkewSeconds)
            || !is_string($jwtId) || !$this->isValidIdentifier($jwtId)) {
            throw new InvalidTokenException('DPoP request binding or temporal claims are invalid.');
        }
        $this->validateOptionalBinding($claims, 'ath', $accessToken === null ? null : Base64Url::encode(hash('sha256', $accessToken, true)));
        $this->validateOptionalBinding($claims, 'nonce', $nonce);
        $thumbprint = new Jwks()->thumbprint($jwk);
        if (!$replayStore->consume($thumbprint, $jwtId, $issuedAt + $maximumAgeSeconds)) {
            throw new InvalidTokenException('DPoP proof was already consumed.');
        }

        return ['claims' => $claims, 'publicJwk' => $jwk, 'keyThumbprint' => $thumbprint];
    }

    /** @param array<string, mixed> $jwk */
    private function assertConfiguredPublicJwk(array $jwk): void
    {
        try {
            $this->assertPublicJwk($jwk);
        } catch (InvalidTokenException $exception) {
            throw new ConfigurationException($exception->getMessage(), 0, $exception);
        }
    }

    private function assertOptionalIdentifier(?string $value, string $label): void
    {
        if ($value !== null && !$this->isValidIdentifier($value)) {
            throw new ConfigurationException(sprintf('%s is invalid.', $label));
        }
    }

    /** @param array<string, mixed> $jwk */
    private function assertPublicJwk(array $jwk): void
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as $privateMember) {
            if (array_key_exists($privateMember, $jwk)) {
                throw new InvalidTokenException('DPoP header must contain only a public asymmetric JWK.');
            }
        }
        if (!in_array($jwk['kty'] ?? null, ['RSA', 'EC', 'OKP'], true)) {
            throw new InvalidTokenException('DPoP requires a public asymmetric JWK.');
        }
    }

    private function assertTemporalPolicy(int $maximumAgeSeconds, int $maximumFutureSkewSeconds): void
    {
        if ($maximumAgeSeconds < 1 || $maximumAgeSeconds > self::MAX_PROOF_AGE_SECONDS) {
            throw new ConfigurationException('DPoP maximum proof age must be between 1 and 3600 seconds.');
        }
        if ($maximumFutureSkewSeconds < 0 || $maximumFutureSkewSeconds > self::MAX_FUTURE_SKEW_SECONDS) {
            throw new ConfigurationException('DPoP maximum future skew must be between 0 and 300 seconds.');
        }
    }

    private function isAcceptedIssuedAt(int $issuedAt, int $current, int $maximumAgeSeconds, int $maximumFutureSkewSeconds): bool
    {
        return $issuedAt <= $current + $maximumFutureSkewSeconds
            && $issuedAt >= $current - $maximumAgeSeconds;
    }

    private function isValidIdentifier(string $value): bool
    {
        return $value !== ''
            && strlen($value) <= self::MAX_IDENTIFIER_BYTES
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    private function normalizeMethod(string $method): string
    {
        $method = strtoupper($method);
        if (preg_match("/\\A[!#$%&'*+.^_`|~0-9A-Z-]+\\z/D", $method) !== 1) {
            throw new ConfigurationException('DPoP htm must use valid HTTP token syntax.');
        }

        return $method;
    }

    private function normalizeUri(string $uri): string
    {
        $parts = parse_url($uri);
        if (!is_array($parts) || !is_string($parts['scheme'] ?? null) || !is_string($parts['host'] ?? null)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new ConfigurationException('DPoP htu must be an absolute HTTP URI without credentials or fragment.');
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new ConfigurationException('DPoP htu scheme is unsupported.');
        }
        $port = $parts['port'] ?? null;
        $authority = strtolower($parts['host']);
        if (str_contains($authority, ':') && !str_starts_with($authority, '[')) {
            $authority = '[' . $authority . ']';
        }
        if (is_int($port) && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))) {
            $authority .= ':' . $port;
        }

        return $scheme . '://' . $authority . ($parts['path'] ?? '/');
    }

    /** @return array{array<string, mixed>, array<string, mixed>} */
    private function parse(#[\SensitiveParameter] string $proof): array
    {
        $parts = explode('.', $proof);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new InvalidTokenException('DPoP proof must be a compact JWS.');
        }

        return [
            JwtToken::decodeJsonObject(Base64Url::decode($parts[0]), 'DPoP header'),
            JwtToken::decodeJsonObject(Base64Url::decode($parts[1]), 'DPoP claims'),
        ];
    }

    /**
     * @param array<mixed, mixed> $input
     * @return array<string, mixed>
     */
    private function stringKeyArray(array $input): array
    {
        $result = [];
        foreach ($input as $name => $value) {
            if (is_string($name)) {
                $result[$name] = $value;
            }
        }

        return $result;
    }

    /** @param array<string, mixed> $claims */
    private function validateOptionalBinding(array $claims, string $name, ?string $expected): void
    {
        if ($expected !== null && (!is_string($claims[$name] ?? null) || !hash_equals($expected, $claims[$name]))) {
            throw new InvalidTokenException(sprintf('DPoP %s binding does not match.', $name));
        }
    }
}
