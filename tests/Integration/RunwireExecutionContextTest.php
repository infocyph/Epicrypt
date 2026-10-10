<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\Response;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;
use Infocyph\Runwire\Coroutine\CoroutineRuntime;
use Infocyph\Runwire\Coroutine\CoroutineScope;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\Runtime\Enum\RuntimeDriver;
use Infocyph\Runwire\RuntimeCapabilities;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\RuntimeContext;

it('uses only borrowed runtime objects and supports checkpoints without a scheduler', function () {
    $runtime = RuntimeContext::standalone();
    $context = new RunwireExecutionContext($runtime, checkpointEvery: 1);

    expect($context->runtime)->toBe($runtime)
        ->and($context->scope)->toBeNull()
        ->and($context->request)->toBeNull();
    $context->checkpoint();
    $context->checkpoint();
    expect($runtime->pid)->toBe(getmypid());
});

it('rejects missing lifecycle integrity, wrong PID, invalid intervals, and replaced requests', function () {
    $runtime = RuntimeContext::standalone();
    expect(fn () => new RunwireExecutionContext($runtime, checkpointEvery: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn () => new RunwireExecutionContext($runtime, checkpointEvery: 1_000_001))->toThrow(InvalidArgumentException::class);

    $otherRuntime = RuntimeContext::fromCapabilities($runtime->capabilities, 'standalone', pid: getmypid() + 1);
    expect(fn () => new RunwireExecutionContext($otherRuntime))->toThrow(LogicException::class);
    expect(fn () => new RunwireExecutionContext($runtime, RequestContext::standalone()))
        ->toThrow(LogicException::class);
});

it('rejects cancelled and completed request lifecycles without owning their termination', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $context = new RunwireExecutionContext($runtime, $request);
    $context->checkpoint();

    expect($request->completed())->toBeFalse();
    $request->cancel(CancellationReason::HOST_CANCELLED);
    expect(fn () => $context->checkpoint())->toThrow(CancelledException::class);

    $completed = RequestContext::create($runtime);
    $completed->complete();
    expect(fn () => new RunwireExecutionContext($runtime, $completed))->toThrow(LogicException::class);
});

it('forwards one borrowed context through direct and intermediary stream operations without owning resources', function () {
    $runtime = RuntimeContext::standalone();
    $context = new RunwireExecutionContext($runtime, RequestContext::create($runtime), checkpointEvery: 1);
    $bridge = static fn(RunwireExecutionContext $borrowed, callable $operation): mixed => $operation($borrowed);
    $source = fopen('php://temp', 'w+b');
    $encrypted = fopen('php://temp', 'w+b');
    $restored = fopen('php://temp', 'w+b');
    fwrite($source, str_repeat('runwire-borrowed', 1000));
    rewind($source);
    $secret = new SecretStream(random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES));

    try {
        $bytes = $bridge($context, static fn(RunwireExecutionContext $forwarded): int =>
            $secret->encryptStream($source, $encrypted, 1024, context: $forwarded));
        expect($bytes)->toBeGreaterThan(0);
        rewind($encrypted);
        $secret->decryptStream($encrypted, $restored, 1024, $context);
        rewind($restored);
        expect(stream_get_contents($restored))->toBe(str_repeat('runwire-borrowed', 1000))
            ->and($context->runtime)->toBe($runtime);

        rewind($restored);
        $digest = hash('sha256', str_repeat('runwire-borrowed', 1000));
        expect((new FileHasher())->verifyStream($restored, $digest, context: $context))->toBeTrue();
        expect(is_resource($source))->toBeTrue()
            ->and(is_resource($restored))->toBeTrue()
            ->and($context->request->completed())->toBeFalse();
    } finally {
        fclose($source);
        fclose($encrypted);
        fclose($restored);
    }
});

it('does not publish or replace a local output for an already cancelled borrowed request', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $context = new RunwireExecutionContext($runtime, $request);
    $directory = sys_get_temp_dir() . '/epicrypt-runwire-' . bin2hex(random_bytes(8));
    mkdir($directory, 0700);
    $source = $directory . '/source.txt';
    $target = $directory . '/target.txt';
    file_put_contents($source, 'new-secret-data');
    file_put_contents($target, 'previous-output');
    $key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
    $request->cancel(CancellationReason::HOST_CANCELLED);

    try {
        expect(fn () => (new SecretStream($key))->encrypt($source, $target, context: $context))
            ->toThrow(CancelledException::class);
        expect(fn () => (new FileProtector())->protectWithBinaryKey(
            $source,
            $target,
            $key,
            new ProtectionOptions('runwire-cancellation'),
            context: $context,
        ))->toThrow(CancelledException::class);
        expect(file_get_contents($target))->toBe('previous-output')
            ->and(glob($directory . '/.epicrypt-*') ?: [])->toBe([]);
    } finally {
        unlink($source);
        unlink($target);
        rmdir($directory);
    }
});

it('does not return stale JWKS when host cancellation occurs during HTTP refresh', function () {
    $runtime = RuntimeContext::standalone();
    $request = RequestContext::create($runtime);
    $context = new RunwireExecutionContext($runtime, $request);
    $client = new class($request) implements ClientInterface {
        public function __construct(private RequestContext $request) {}

        public function sendRequest(RequestInterface $request): ResponseInterface
        {
            unset($request);
            $this->request->cancel(CancellationReason::HOST_CANCELLED);

            return new Response(200, ['Content-Type' => 'application/jwk-set+json'], '{"keys":[]}');
        }
    };
    $cache = $this->createMock(CacheInterface::class);
    $cache->method('get')->willReturn([
        'jwks' => ['keys' => []],
        'freshUntil' => 999,
        'staleUntil' => 1200,
    ]);
    $resolver = new class implements RemoteJoseHostResolverInterface {
        public function resolve(string $hostname): array
        {
            unset($hostname);

            return ['8.8.8.8'];
        }
    };
    $clock = new class implements ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@1000');
        }
    };
    $remote = new RemoteJwks(
        $client,
        new Psr17Factory(),
        new RemoteJwksConfiguration('https://issuer.example', 'https://issuer.example/jwks'),
        $cache,
        $clock,
        $resolver,
    );

    expect(fn () => $remote->load(context: $context))->toThrow(CancelledException::class);
});

it('checks liveness and yields only inside a live borrowed host coroutine scope', function () {
    $capabilities = new RuntimeCapabilities(RuntimeDriver::NATIVE, supportsRunwireCoroutines: true);
    $runtime = RuntimeContext::fromCapabilities($capabilities, 'epicrypt-test');
    $request = RequestContext::create($runtime);
    $events = [];
    $borrowed = null;

    $digest = (new CoroutineRuntime())->run(function (CoroutineScope $scope) use (
        $runtime,
        $request,
        &$events,
        &$borrowed,
    ): string {
        $borrowed = new RunwireExecutionContext($runtime, $request, $scope, checkpointEvery: 1);
        $task = $scope->spawn(static function () use (&$events): void {
            $events[] = 'host-task';
        });
        $stream = fopen('php://temp', 'w+b');
        fwrite($stream, str_repeat('owned-by-host', 4096));
        rewind($stream);

        try {
            $hash = (new FileHasher())->hashStream($stream, context: $borrowed);
            $task->await();
            $events[] = 'epicrypt-complete';

            return $hash;
        } finally {
            fclose($stream);
        }
    });
    expect($digest)->toBe(hash('sha256', str_repeat('owned-by-host', 4096)))
        ->and($events)->toBe(['host-task', 'epicrypt-complete'])
        ->and($request->completed())->toBeFalse();
    expect(fn () => $borrowed->checkpoint())->toThrow(LogicException::class);
});

it('preserves separate borrowed request cancellation across interleaved host tasks', function () {
    $runtime = RuntimeContext::fromCapabilities(
        new RuntimeCapabilities(RuntimeDriver::NATIVE, supportsRunwireCoroutines: true),
        'epicrypt-isolated',
    );
    $first = RequestContext::create($runtime);
    $second = RequestContext::create($runtime);
    $events = [];

    (new CoroutineRuntime())->run(function (CoroutineScope $scope) use ($runtime, $first, $second, &$events): void {
        $one = new RunwireExecutionContext($runtime, $first, $scope, checkpointEvery: 1);
        $two = new RunwireExecutionContext($runtime, $second, $scope, checkpointEvery: 1);
        $a = $scope->spawn(static function () use ($first, $one, &$events): void {
            $first->cancel(CancellationReason::HOST_CANCELLED);
            try {
                $one->checkpoint();
            } catch (CancelledException) {
                $events['a'] = 'cancelled';
            }
        });
        $b = $scope->spawn(static function () use ($two, &$events): void {
            $two->checkpoint();
            $events['b'] = 'active';
        });
        $a->await();
        $b->await();
        $two->checkpoint();
    });

    expect($events)->toBe(['a' => 'cancelled', 'b' => 'active'])
        ->and($second->completed())->toBeFalse()
        ->and($first->completed())->toBeFalse();
});
