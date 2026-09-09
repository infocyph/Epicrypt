<?php

declare(strict_types=1);

use Http\Mock\Client;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Clock\ClockInterface;
use Psr\SimpleCache\CacheInterface;

function remoteJwksClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(public int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@' . $this->timestamp);
        }
    };
}

function remoteJwksCache(): CacheInterface
{
    return new class implements CacheInterface {
        /** @var array<string, mixed> */
        public array $values = [];

        public function get(string $key, mixed $default = null): mixed
        {
            return $this->values[$key] ?? $default;
        }

        public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
        {
            unset($ttl);
            $this->values[$key] = $value;

            return true;
        }

        public function delete(string $key): bool
        {
            unset($this->values[$key]);

            return true;
        }

        public function clear(): bool
        {
            $this->values = [];

            return true;
        }

        public function getMultiple(iterable $keys, mixed $default = null): iterable
        {
            foreach ($keys as $key) {
                yield $key => $this->get($key, $default);
            }
        }

        public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
        {
            foreach ($values as $key => $value) {
                $this->set((string) $key, $value, $ttl);
            }

            return true;
        }

        public function deleteMultiple(iterable $keys): bool
        {
            foreach ($keys as $key) {
                $this->delete($key);
            }

            return true;
        }

        public function has(string $key): bool
        {
            return array_key_exists($key, $this->values);
        }
    };
}

/** @param array<string, list<string>> $answers */
function remoteJwksResolver(array $answers = []): RemoteJoseHostResolverInterface
{
    $answers += [
        'cdn.example' => ['9.9.9.9'],
        'issuer.example' => ['1.1.1.1'],
        'keys.example' => ['8.8.8.8'],
    ];

    return new class($answers) implements RemoteJoseHostResolverInterface {
        /** @param array<string, list<string>> $answers */
        public function __construct(private array $answers) {}

        public function resolve(string $hostname): array
        {
            return $this->answers[$hostname] ?? [];
        }
    };
}

it('uses one forced refresh to resolve a rolled over remote key', function () {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $old = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $current = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $jwks = new Jwks();
    $oldSet = ['keys' => [$jwks->exportPublicKeyToJwk($old['public'], 'old', AsymmetricJwtAlgorithm::RS256)]];
    $currentSet = ['keys' => [$jwks->exportPublicKeyToJwk($current['public'], 'current', AsymmetricJwtAlgorithm::RS256)]];
    $client->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode($oldSet, JSON_THROW_ON_ERROR)));
    $client->addResponse(new Response(200, ['Content-Type' => 'application/jwk-set+json'], json_encode($currentSet, JSON_THROW_ON_ERROR)));

    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration(
            'https://issuer.example',
            'https://keys.example/jwks',
            allowedJwksHosts: ['keys.example'],
        ),
        hostResolver: remoteJwksResolver(),
    );

    expect($remote->resolve('current', AsymmetricJwtAlgorithm::RS256))->toContain('PUBLIC KEY')
        ->and($client->getRequests())->toHaveCount(2);
});

it('binds discovery to the configured issuer and enforces response bounds', function () {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $client->addResponse(new Response(200, ['Content-Type' => 'application/json'], json_encode([
        'issuer' => 'https://attacker.example',
        'jwks_uri' => 'https://keys.example/jwks',
    ], JSON_THROW_ON_ERROR)));
    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration('https://issuer.example'),
        hostResolver: remoteJwksResolver(),
    );
    expect(fn () => $remote->load())->toThrow(KeyResolutionException::class);

    $oversized = new Client($factory);
    $oversized->addResponse(new Response(200, ['Content-Type' => 'application/json'], str_repeat('x', 1025)));
    $bounded = new RemoteJwks(
        $oversized,
        $factory,
        new RemoteJwksConfiguration(
            'https://issuer.example',
            'https://keys.example/jwks',
            maximumResponseBytes: 1024,
            allowedJwksHosts: ['keys.example'],
        ),
        hostResolver: remoteJwksResolver(),
    );
    expect(fn () => $bounded->load())->toThrow(KeyResolutionException::class);
});

it('enforces same-host or explicitly allowed JWKS destinations', function () {
    expect(new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'))
        ->toBeInstanceOf(RemoteJwksConfiguration::class)
        ->and(new RemoteJwksConfiguration(
            'https://issuer.example',
            'https://cdn.example/jwks',
            allowedJwksHosts: ['cdn.example'],
        ))->toBeInstanceOf(RemoteJwksConfiguration::class)
        ->and(fn () => new RemoteJwksConfiguration('https://issuer.example', 'https://cdn.example/jwks'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new RemoteJwksConfiguration('http://issuer.example'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new RemoteJwksConfiguration('https://127.0.0.1'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new RemoteJwksConfiguration('https://localhost'))
        ->toThrow(ConfigurationException::class);
});

it('requires approved media types and treats visible redirects as failures', function () {
    $factory = new Psr17Factory();
    foreach ([
        new Response(200, [], '{"keys":[]}'),
        new Response(200, ['Content-Type' => 'text/html'], '{"keys":[]}'),
        new Response(302, ['Location' => 'https://issuer.example/other']),
    ] as $response) {
        $client = new Client($factory);
        $client->addResponse($response);
        $remote = new RemoteJwks(
            $client,
            $factory,
            new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'),
            hostResolver: remoteJwksResolver(),
        );
        expect(fn () => $remote->load())->toThrow(KeyResolutionException::class);
    }
});

it('rejects private reserved mixed empty and malformed DNS answers before sending', function (array $addresses) {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $client->addResponse(new Response(200, ['Content-Type' => 'application/jwk-set+json'], '{"keys":[]}'));
    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'),
        hostResolver: remoteJwksResolver(['issuer.example' => $addresses]),
    );

    expect(fn () => $remote->load())->toThrow(KeyResolutionException::class)
        ->and($client->getRequests())->toHaveCount(0);
})->with([
    'private IPv4' => [['10.0.0.1']],
    'loopback IPv4' => [['127.0.0.1']],
    'link local metadata IPv4' => [['169.254.169.254']],
    'loopback IPv6' => [['::1']],
    'link local IPv6' => [['fe80::1']],
    'IPv4 mapped loopback' => [['::ffff:127.0.0.1']],
    'mixed public and private' => [['1.1.1.1', '10.0.0.1']],
    'empty resolution' => [[]],
    'malformed resolution' => [['not-an-ip']],
]);

it('re-resolves before every outbound request and fails a rebinding attempt closed', function () {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $client->addResponse(new Response(200, ['Content-Type' => 'application/jwk-set+json'], '{"keys":[]}'));
    $resolver = new class implements RemoteJoseHostResolverInterface {
        public int $calls = 0;

        public function resolve(string $hostname): array
        {
            unset($hostname);

            return ++$this->calls === 1 ? ['1.1.1.1'] : ['10.0.0.1'];
        }
    };
    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'),
        hostResolver: $resolver,
    );

    expect($remote->load())->toBe(['keys' => []]);
    expect(fn () => $remote->load())->toThrow(KeyResolutionException::class)
        ->and($resolver->calls)->toBe(2)
        ->and($client->getRequests())->toHaveCount(1);
});

it('honors max-age no-cache and no-store using the injected clock', function (string $cacheControl, int $expectedRequests) {
    $factory = new Psr17Factory();
    $client = new Client($factory);
    $headers = ['Content-Type' => 'application/jwk-set+json', 'Cache-Control' => $cacheControl];
    $client->addResponse(new Response(200, $headers, '{"keys":[]}'));
    $client->addResponse(new Response(200, $headers, '{"keys":[]}'));
    $cache = remoteJwksCache();
    $remote = new RemoteJwks(
        $client,
        $factory,
        new RemoteJwksConfiguration(
            'https://issuer.example',
            'https://issuer.example/jwks',
            minimumTtl: 1,
            maximumTtl: 300,
        ),
        $cache,
        remoteJwksClock(1_700_000_000),
        remoteJwksResolver(),
    );

    $remote->load();
    $remote->load();
    expect($client->getRequests())->toHaveCount($expectedRequests);
})->with([
    'bounded max-age cache hit' => ['max-age=120', 1],
    'no-cache forces retrieval' => ['no-cache, max-age=120', 2],
    'no-store prevents persistence' => ['no-store, max-age=120', 2],
]);
