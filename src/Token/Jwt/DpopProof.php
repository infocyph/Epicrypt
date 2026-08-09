<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;

final class DpopProof
{
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
        ?string $accessToken = null,
        ?string $nonce = null,
        ?int $issuedAt = null,
        ?string $jwtId = null,
    ): string {
        $this->assertPublicJwk($publicJwk);
        $claims = [
            'htm' => strtoupper($method),
            'htu' => $this->normalizeUri($uri),
            'iat' => $issuedAt ?? time(),
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

    /**
     * @return array<string, mixed>
     */
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
        ?int $now = null,
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
            $now,
        )['claims'];
    }

    /**
     * @return array{claims: array<string, mixed>, publicJwk: array<string, mixed>, keyThumbprint: string}
     */
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
        ?int $now = null,
    ): array {
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
        $current = $now ?? time();
        $issuedAt = $claims['iat'] ?? null;
        $jwtId = $claims['jti'] ?? null;
        if (($claims['htm'] ?? null) !== strtoupper($method) || ($claims['htu'] ?? null) !== $this->normalizeUri($uri)
            || !is_int($issuedAt) || abs($current - $issuedAt) > $maximumAgeSeconds
            || !is_string($jwtId) || $jwtId === '' || strlen($jwtId) > 128) {
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

    private function normalizeUri(string $uri): string
    {
        $parts = parse_url($uri);
        if (!is_array($parts) || !is_string($parts['scheme'] ?? null) || !is_string($parts['host'] ?? null)
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw new InvalidTokenException('DPoP htu must be an absolute HTTP URI without credentials or fragment.');
        }
        $scheme = strtolower($parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new InvalidTokenException('DPoP htu scheme is unsupported.');
        }
        $port = $parts['port'] ?? null;
        $authority = strtolower($parts['host']);
        if (is_int($port) && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))) {
            $authority .= ':' . $port;
        }

        return $scheme . '://' . $authority . ($parts['path'] ?? '/');
    }

    /** @return array{array<string, mixed>, array<string, mixed>} */
    private function parse(string $proof): array
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
