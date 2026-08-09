<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\RemoteJoseResource;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\SimpleCache\CacheInterface;

final readonly class RemoteJwks
{
    private string $cacheKey;

    private RemoteJoseResource $resource;

    public function __construct(
        ClientInterface $client,
        RequestFactoryInterface $requestFactory,
        private RemoteJwksConfiguration $configuration,
        private ?CacheInterface $cache = null,
    ) {
        $this->resource = new RemoteJoseResource($client, $requestFactory, $configuration->maximumResponseBytes);
        $this->cacheKey = 'epicrypt:jwks:' . hash('sha256', $configuration->issuer . "\0" . ($configuration->jwksUri ?? 'discovery'));
    }

    /** @return array{keys: list<array<string, mixed>>} */
    public function load(bool $forceRefresh = false): array
    {
        $cached = $this->cached();
        if (!$forceRefresh && $cached !== null && $cached['freshUntil'] >= time()) {
            return $cached['jwks'];
        }

        try {
            [$jwks, $maxAge] = $this->fetch();
            $ttl = max($this->configuration->minimumTtl, min($this->configuration->maximumTtl, $maxAge ?? $this->configuration->maximumTtl));
            $entry = [
                'jwks' => $jwks,
                'freshUntil' => time() + $ttl,
                'staleUntil' => time() + $ttl + $this->configuration->staleTtl,
            ];
            $this->cache?->set($this->cacheKey, $entry, $ttl + $this->configuration->staleTtl);

            return $jwks;
        } catch (\Throwable $exception) {
            if (!$forceRefresh && $cached !== null && $cached['staleUntil'] >= time()) {
                return $cached['jwks'];
            }
            if ($exception instanceof KeyResolutionException) {
                throw $exception;
            }

            throw new KeyResolutionException('Remote JWKS resolution failed.', 0, $exception);
        }
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
            || !is_array($entry['jwks'] ?? null) || !is_array($entry['jwks']['keys'] ?? null)) {
            return null;
        }
        $keys = [];
        foreach ($entry['jwks']['keys'] as $key) {
            if (!is_array($key)) {
                return null;
            }
            $normalized = [];
            foreach ($key as $name => $value) {
                if (is_string($name)) {
                    $normalized[$name] = $value;
                }
            }
            $keys[] = $normalized;
        }

        return ['jwks' => ['keys' => $keys], 'freshUntil' => $entry['freshUntil'], 'staleUntil' => $entry['staleUntil']];
    }

    /** @return array{array{keys: list<array<string, mixed>>}, int|null} */
    private function fetch(): array
    {
        $uri = $this->configuration->jwksUri;
        if ($uri === null) {
            [$metadata] = $this->resource->fetch($this->configuration->discoveryUri());
            if (($metadata['issuer'] ?? null) !== $this->configuration->issuer || !is_string($metadata['jwks_uri'] ?? null)) {
                throw new KeyResolutionException('OpenID discovery metadata does not match the configured issuer.');
            }
            $uri = $metadata['jwks_uri'];
            $this->configuration->validateUrl($uri);
        }
        [$document, $maxAge] = $this->resource->fetch($uri);
        $keys = $document['keys'] ?? null;
        if (!is_array($keys) || !array_is_list($keys) || count($keys) > $this->configuration->maximumKeys) {
            throw new KeyResolutionException('Remote JWKS keys collection is invalid or exceeds its bound.');
        }
        $normalized = [];
        foreach ($keys as $key) {
            if (!is_array($key)) {
                throw new KeyResolutionException('Remote JWKS contains a non-object key.');
            }
            $entry = [];
            foreach ($key as $name => $value) {
                if (is_string($name)) {
                    $entry[$name] = $value;
                }
            }
            $normalized[] = $entry;
        }

        return [['keys' => $normalized], $maxAge];
    }
}
