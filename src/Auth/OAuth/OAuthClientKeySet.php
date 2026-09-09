<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;

final readonly class OAuthClientKeySet
{
    private const int MAX_KEYS = 16;

    /** @var non-empty-list<array<string, mixed>> */
    private array $keys;

    /** @param array{keys?: mixed} $jwks */
    public function __construct(array $jwks)
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys)
            || $keys === []
            || !array_is_list($keys)
            || count($keys) > self::MAX_KEYS) {
            throw new ConfigurationException('OAuth client JWKS must contain a bounded non-empty keys list.');
        }

        $seen = [];
        $normalized = [];
        foreach ($keys as $key) {
            if (!is_array($key) || array_is_list($key)) {
                throw new ConfigurationException('OAuth client JWKS entries must be objects.');
            }
            $candidate = self::stringKeyArray($key);
            self::assertPublicSigningKey($candidate);
            $kid = $candidate['kid'] ?? null;
            if (!is_string($kid) || !JosePolicy::isKeyId($kid) || isset($seen[$kid])) {
                throw new ConfigurationException('OAuth client JWKS requires unique Base64URL-safe kid values.');
            }
            $algorithm = $candidate['alg'] ?? null;
            if (!is_string($algorithm) || AsymmetricJwtAlgorithm::tryFrom($algorithm) === null) {
                throw new ConfigurationException('OAuth client JWK requires an explicitly supported asymmetric alg.');
            }

            try {
                self::importPublicKey($candidate, AsymmetricJwtAlgorithm::from($algorithm));
            } catch (KeyResolutionException $exception) {
                throw new ConfigurationException('OAuth client JWK is not a usable public signing key.', 0, $exception);
            }

            $seen[$kid] = true;
            $normalized[] = $candidate;
        }

        /** @var non-empty-list<array<string, mixed>> $normalized */
        $this->keys = $normalized;
    }

    /** @return array{keys: non-empty-list<array<string, mixed>>} */
    public function toArray(): array
    {
        return ['keys' => $this->keys];
    }

    /** @return list<AsymmetricJwtAlgorithm> */
    public function algorithms(): array
    {
        $seen = [];
        $algorithms = [];
        foreach ($this->keys as $key) {
            $algorithm = AsymmetricJwtAlgorithm::from((string) $key['alg']);
            if (isset($seen[$algorithm->value])) {
                continue;
            }
            $seen[$algorithm->value] = true;
            $algorithms[] = $algorithm;
        }

        return $algorithms;
    }

    public function resolvePublicKey(?string $kid, AsymmetricJwtAlgorithm $algorithm): string
    {
        $matches = [];
        foreach ($this->keys as $key) {
            if (($key['alg'] ?? null) !== $algorithm->value) {
                continue;
            }
            if ($kid !== null && ($key['kid'] ?? null) !== $kid) {
                continue;
            }
            $matches[] = $key;
        }

        if (count($matches) !== 1) {
            throw new KeyResolutionException(
                $kid === null
                    ? 'OAuth client assertion without kid requires exactly one key for its algorithm.'
                    : 'OAuth client assertion key could not be resolved uniquely.',
            );
        }

        return self::importPublicKey($matches[0], $algorithm);
    }

    /** @param array<string, mixed> $jwk */
    private static function assertPublicSigningKey(array $jwk): void
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $privateMember) {
            if (array_key_exists($privateMember, $jwk)) {
                throw new ConfigurationException('OAuth client JWKS must not contain private or symmetric key material.');
            }
        }
        if (($jwk['use'] ?? 'sig') !== 'sig') {
            throw new ConfigurationException('OAuth client assertion JWK use must be sig.');
        }
        if (isset($jwk['key_ops']) && $jwk['key_ops'] !== ['verify']) {
            throw new ConfigurationException('OAuth client assertion JWK key_ops must be exactly ["verify"] when provided.');
        }
    }

    /** @param array<string, mixed> $jwk */
    private static function importPublicKey(array $jwk, AsymmetricJwtAlgorithm $algorithm): string
    {
        $jwks = new Jwks();

        return $algorithm === AsymmetricJwtAlgorithm::EDDSA
            ? $jwks->importOkpPublicKey($jwk, $algorithm->value, 'Ed25519')
            : $jwks->importPublicKeyFromJwk($jwk, $algorithm);
    }

    /**
     * @param array<array-key, mixed> $input
     * @return array<string, mixed>
     */
    private static function stringKeyArray(array $input): array
    {
        $result = [];
        foreach ($input as $name => $value) {
            if (!is_string($name)) {
                throw new ConfigurationException('OAuth client JWK member names must be strings.');
            }
            $result[$name] = $value;
        }

        return $result;
    }
}
