<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JosePolicy;
use Infocyph\Epicrypt\Token\Jwt\Support\NativeRemoteJoseHostResolver;
use Infocyph\Epicrypt\Token\Jwt\Support\RemoteJoseResource;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;
use Throwable;

final readonly class RemoteJwks
{
    private string $cacheKey;

    private RemoteJoseResource $resource;

    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requestFactory,
        private RemoteJwksConfiguration $configuration,
        private ?CacheInterface $cache = null,
        private ClockInterface $clock = new SystemClock(),
        ?RemoteJoseHostResolverInterface $hostResolver = null,
    ) {
        $this->resource = new RemoteJoseResource(
            $client,
            $requestFactory,
            $configuration->maximumResponseBytes,
            $configuration->maximumKeys,
            $hostResolver ?? new NativeRemoteJoseHostResolver(),
        );
        $hosts = array_values(array_unique($configuration->allowedJwksHosts));
        sort($hosts, SORT_STRING);
        $identity = [
            $configuration->issuer,
            $configuration->jwksUri,
            $configuration->minimumTtl,
            $configuration->maximumTtl,
            $configuration->staleTtl,
            $configuration->maximumResponseBytes,
            $configuration->maximumKeys,
            $configuration->allowHttp,
            $hosts,
        ];
        $this->cacheKey = hash('sha256', "epicrypt\0jwks\0v2\0" . json_encode($identity, JSON_THROW_ON_ERROR));
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function load(bool $forceRefresh = false): array
    {
        try {
            $cached = $forceRefresh ? null : $this->cached();
        } catch (Throwable $exception) {
            throw new KeyResolutionException('Remote JWKS cache lookup failed.', 0, $exception);
        }
        $now = $this->clock->now()->getTimestamp();
        if (!$forceRefresh && $cached !== null && $cached['freshUntil'] > $now) {
            return $cached['jwks'];
        }

        try {
            [$jwks, $cachePolicy] = $this->fetch();
        } catch (Throwable $exception) {
            if (!$forceRefresh && $cached !== null && $cached['staleUntil'] > $now) {
                return $cached['jwks'];
            }
            if ($exception instanceof KeyResolutionException) {
                throw $exception;
            }

            throw new KeyResolutionException('Remote JWKS resolution failed.', 0, $exception);
        }

        return $this->storeFetched($jwks, $cachePolicy, $now);
    }

    public function resolve(string $kid, AsymmetricJwtAlgorithm $algorithm): string
    {
        $jwks = $this->load(false);

        try {
            return new Jwks()->resolvePublicKeyByKid($jwks, $kid, $algorithm);
        } catch (KeyResolutionException) {
            $jwks = $this->load(true);

            return new Jwks()->resolvePublicKeyByKid($jwks, $kid, $algorithm);
        }
    }

    /** @return array{jwks: array{keys: list<array<string, mixed>>}, freshUntil: int, staleUntil: int}|null */
    private function cached(): ?array
    {
        $entry = $this->cache?->get($this->cacheKey);
        if (!is_array($entry) || !is_int($entry['freshUntil'] ?? null) || !is_int($entry['staleUntil'] ?? null)
            || !is_array($entry['jwks'] ?? null)) {
            return null;
        }
        $keys = $this->normalizeKeys($entry['jwks']['keys'] ?? null);
        if ($keys === null || $entry['staleUntil'] < $entry['freshUntil']) {
            return null;
        }

        return ['jwks' => ['keys' => $keys], 'freshUntil' => $entry['freshUntil'], 'staleUntil' => $entry['staleUntil']];
    }

    /** @return array{array{keys: list<array<string, mixed>>}, array{maxAge: int|null, noStore: bool, noCache: bool}} */
    private function fetch(): array
    {
        $uri = $this->configuration->jwksUri;
        if ($uri === null) {
            [$metadata] = $this->resource->fetch($this->configuration->discoveryUri());
            if (($metadata['issuer'] ?? null) !== $this->configuration->issuer || !is_string($metadata['jwks_uri'] ?? null)) {
                throw new KeyResolutionException('OpenID discovery metadata does not match the configured issuer.');
            }
            $uri = $metadata['jwks_uri'];
            $this->configuration->validateJwksUrl($uri);
        }
        [$document, $cachePolicy] = $this->resource->fetch($uri, jwks: true);
        $keys = $this->normalizeKeys($document['keys'] ?? null);
        if ($keys === null) {
            throw new KeyResolutionException('Remote JWKS keys collection is invalid or exceeds its bound.');
        }

        return [['keys' => $keys], $cachePolicy];
    }

    /** @return list<array<string, mixed>>|null */
    private function normalizeKeys(mixed $keys): ?array
    {
        if (!is_array($keys) || !array_is_list($keys) || count($keys) > $this->configuration->maximumKeys) {
            return null;
        }

        $normalized = [];
        foreach ($keys as $key) {
            if (!is_array($key)) {
                return null;
            }

            try {
                JosePolicy::assertMemberCount($key, JosePolicy::MAX_JWK_MEMBERS, 'Remote JWK');
            } catch (Throwable) {
                return null;
            }
            $entry = [];
            foreach ($key as $name => $value) {
                if (!is_string($name)) {
                    return null;
                }
                $entry[$name] = $value;
            }
            $normalized[] = $entry;
        }

        return $normalized;
    }
    /**
     * @param array{keys: list<array<string, mixed>>} $jwks
     * @param array{maxAge: int|null, noStore: bool, noCache: bool} $cachePolicy
     * @return array{keys: list<array<string, mixed>>}
     */
    private function storeFetched(array $jwks, array $cachePolicy, int $now): array
    {
        try {
            if ($cachePolicy['noStore']) {
                if ($this->cache?->delete($this->cacheKey) === false) {
                    throw new KeyResolutionException('Remote JWKS cache invalidation failed.');
                }

                return $jwks;
            }

            $ttl = $cachePolicy['noCache']
                ? 0
                : max($this->configuration->minimumTtl, min(
                    $this->configuration->maximumTtl,
                    $cachePolicy['maxAge'] ?? $this->configuration->maximumTtl,
                ));
            $staleTtl = $cachePolicy['noCache'] ? 0 : $this->configuration->staleTtl;
            $entry = [
                'jwks' => $jwks,
                'freshUntil' => $now + $ttl,
                'staleUntil' => $now + $ttl + $staleTtl,
            ];
            if ($this->cache?->set($this->cacheKey, $entry, max(1, $ttl + $staleTtl)) === false) {
                throw new KeyResolutionException('Remote JWKS cache write failed.');
            }

            return $jwks;
        } catch (Throwable $exception) {
            throw new KeyResolutionException('Remote JWKS cache operation failed.', 0, $exception);
        }
    }
}
