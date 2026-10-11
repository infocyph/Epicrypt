<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\RuntimeContext;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;

require dirname(__DIR__) . '/vendor/autoload.php';

// A deterministic verification endpoint for a caller-controlled test deployment.
// Synthetic keys and the in-memory transport are fixtures, never production services.
$scenario = $_GET['scenario'] ?? 'stream';
$bound = ($_GET['bound'] ?? '0') === '1';
$runtime = RuntimeContext::standalone();
$request = RequestContext::create($runtime);
$context = $bound ? new RunwireExecutionContext($runtime, $request) : null;
$arguments = $context === null ? [] : ['context' => $context];

try {
    if (!in_array($scenario, ['stream', 'jose', 'cancel', 'mixed'], true) || ($scenario === 'cancel' && !$bound)) {
        throw new RuntimeException('Unknown host scenario.');
    }
    if ($scenario === 'stream' || $scenario === 'mixed') {
        $source = __DIR__ . '/host-payload.bin';
        $encrypted = tempnam(sys_get_temp_dir(), 'epicrypt-host-encrypted-');
        $restored = tempnam(sys_get_temp_dir(), 'epicrypt-host-restored-');
        if ($encrypted === false || $restored === false) {
            throw new RuntimeException('Host fixture storage unavailable.');
        }

        try {
            $protector = new FileProtector();
            $options = new ProtectionOptions('release-host/v1');
            $key = str_repeat('K', 32);
            $protector->protectWithBinaryKey($source, $encrypted, $key, $options, 16_384, ...$arguments);
            $protector->unprotectWithBinaryKey($encrypted, $restored, $key, $options, 16_384, ...$arguments);
            $expected = hash('sha256', str_repeat('release-stream-v1', 4096));
            if (!(new FileHasher())->verify($restored, $expected, ...$arguments)) {
                throw new RuntimeException('Protected file content mismatch.');
            }
        } finally {
            unlink($encrypted);
            unlink($restored);
        }
    }
    if ($scenario === 'jose' || $scenario === 'mixed') {
        $key = str_repeat('J', 64);
        $jwt = SymmetricJwt::issuer($key, 'at+jwt')->issue(JwtClaims::issue('release-host', 'subject', ['host'], 60));
        if (!SymmetricJwt::verifier($key, JwtPolicy::accessToken('release-host', 'host'))->verify($jwt)) {
            throw new RuntimeException('JWT validation failed.');
        }
        $cache = new class implements CacheInterface {
            /** @var array<string, mixed> */
            private array $entries = [];

            public function clear(): bool
            {
                $this->entries = [];

                return true;
            }

            public function delete(string $key): bool
            {
                unset($this->entries[$key]);

                return true;
            }

            public function deleteMultiple(iterable $keys): bool
            {
                foreach ($keys as $key) {
                    $this->delete($key);
                }

                return true;
            }

            public function get(string $key, mixed $default = null): mixed
            {
                return $this->entries[$key] ?? $default;
            }

            public function getMultiple(iterable $keys, mixed $default = null): iterable
            {
                foreach ($keys as $key) {
                    yield $key => $this->get($key, $default);
                }
            }

            public function has(string $key): bool
            {
                return array_key_exists($key, $this->entries);
            }

            public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
            {
                unset($ttl);
                $this->entries[$key] = $value;

                return true;
            }

            /** @param iterable<string, mixed> $values */
            public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
            {
                foreach ($values as $key => $value) {
                    $this->set($key, $value, $ttl);
                }

                return true;
            }
        };
        $client = new class implements ClientInterface {
            public int $requests = 0;

            public function sendRequest(RequestInterface $request): ResponseInterface
            {
                unset($request);
                $this->requests++;

                $json = file_get_contents(__DIR__ . '/host-jwks.json');
                if ($json === false) {
                    throw new RuntimeException('JWKS host fixture is unreadable.');
                }

                return new Response(200, ['Content-Type' => 'application/jwk-set+json'], $json);
            }
        };
        $resolver = new class implements RemoteJoseHostResolverInterface {
            public function resolve(string $hostname): array
            {
                unset($hostname);

                return ['8.8.8.8'];
            }
        };
        $remote = new RemoteJwks($client, new Psr17Factory(), new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'), $cache, hostResolver: $resolver);
        $miss = $remote->resolve('release', AsymmetricJwtAlgorithm::ES256, ...$arguments);
        $hit = $remote->resolve('release', AsymmetricJwtAlgorithm::ES256, ...$arguments);
        $expected = file_get_contents(__DIR__ . '/host-public.pem');
        if ($miss !== $expected || $hit !== $expected || $client->requests !== 1) {
            throw new RuntimeException('Remote key resolution/cache validation failed.');
        }
    }
    if (($scenario === 'cancel' || $scenario === 'mixed') && $context !== null) {
        $request->cancel(CancellationReason::HOST_CANCELLED);
        $stream = fopen('php://temp', 'w+b');
        if ($stream === false) {
            throw new RuntimeException('Cancellation host fixture stream unavailable.');
        }

        try {
            try {
                (new FileHasher())->hashStream($stream, context: $context);

                throw new RuntimeException('Cancelled hash returned success.');
            } catch (CancelledException) {
                // Cancellation is the expected successful host outcome for this route.
            }
        } finally {
            fclose($stream);
        }
    }
    if ($request->completed()) {
        throw new RuntimeException('Library completed the host request.');
    }
    $request->complete();
    header('Content-Type: text/plain');
    header('X-Epicrypt-Worker: ' . getmypid());
    file_put_contents('php://output', 'release-health-ok');
} catch (Throwable $exception) {
    error_log((string) $exception);
    http_response_code(500);
    file_put_contents('php://output', 'release-workload-failed');
}
