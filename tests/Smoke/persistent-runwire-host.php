<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
use Infocyph\Runwire\Exception\CancelledException;
use Infocyph\Runwire\RequestContext;
use Infocyph\Runwire\Runtime\Enum\CancellationReason;
use Infocyph\Runwire\RuntimeContext;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

const ITERATIONS = 2_000;
const MAX_GROWTH_BYTES = 2_097_152;

$runtime = RuntimeContext::standalone();
$hasher = new FileHasher();
$key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
$cipher = new SecretStream($key);
$payloads = ['tenant-a' => str_repeat('A', 2048), 'tenant-b' => str_repeat('B', 2048)];
$hashes = array_map(static fn (string $payload): string => hash('sha256', $payload), $payloads);
$startPid = getmypid();
$verified = 0;

$serve = static function (string $tenant) use ($runtime, $hasher, $cipher, $payloads, $hashes, &$verified): void {
    $request = RequestContext::create($runtime);
    $context = new RunwireExecutionContext($runtime, $request, checkpointEvery: 1);
    $input = fopen('php://temp', 'w+b');
    $encrypted = fopen('php://temp', 'w+b');
    $output = fopen('php://temp', 'w+b');
    if ($input === false || $encrypted === false || $output === false) {
        throw new RuntimeException('Unable to acquire simulated host streams.');
    }

    try {
        fwrite($input, $payloads[$tenant]);
        rewind($input);
        $cipher->encryptStream($input, $encrypted, 1024, $context);
        rewind($encrypted);
        $cipher->decryptStream($encrypted, $output, 1024, $context);
        rewind($output);
        if (!$hasher->verifyStream($output, $hashes[$tenant], context: $context)) {
            throw new RuntimeException('Host tenant content was corrupted or crossed request boundaries.');
        }
        rewind($output);
        if ($hasher->verifyStream($output, $hashes[$tenant === 'tenant-a' ? 'tenant-b' : 'tenant-a'], context: $context)) {
            throw new RuntimeException('Host tenant isolation failed.');
        }
        $verified++;
        $request->complete();
        try {
            $context->checkpoint();
            throw new RuntimeException('Completed request retained an active borrowed context.');
        } catch (LogicException) {
            // A completed request must not be reused by the next request.
        }
    } finally {
        fclose($input);
        fclose($encrypted);
        fclose($output);
    }
};

for ($i = 0; $i < 100; $i++) {
    $serve($i % 2 === 0 ? 'tenant-a' : 'tenant-b');
}
gc_collect_cycles();
$before = memory_get_usage(false);
$peakBefore = memory_get_peak_usage(true);
for ($i = 0; $i < ITERATIONS; $i++) {
    $serve($i % 2 === 0 ? 'tenant-a' : 'tenant-b');
    if ($i % 100 === 0) {
        $a = RequestContext::create($runtime);
        $b = RequestContext::create($runtime);
        $cancelled = new RunwireExecutionContext($runtime, $a);
        $active = new RunwireExecutionContext($runtime, $b);
        $a->cancel(CancellationReason::HOST_CANCELLED);
        try {
            $cancelled->checkpoint();
            throw new RuntimeException('Cancelled tenant request continued.');
        } catch (CancelledException) {
            $active->checkpoint();
        }
        $b->complete();
    }
}
gc_collect_cycles();
$after = memory_get_usage(false);
$growth = max(0, $after - $before);
if ($growth > MAX_GROWTH_BYTES || getmypid() !== $startPid) {
    throw new RuntimeException('Persistent host process integrity or memory-growth guard failed.');
}

fwrite(STDOUT, json_encode([
    'php' => PHP_VERSION,
    'mode' => 'long-lived host process / borrowed standalone Runwire',
    'pid' => $startPid,
    'verified' => $verified,
    'isolated_requests' => ITERATIONS,
    'cancelled_request_checks' => intdiv(ITERATIONS - 1, 100) + 1,
    'heap_before_bytes' => $before,
    'heap_after_bytes' => $after,
    'heap_growth_bytes' => $growth,
    'peak_allocated_bytes' => max($peakBefore, memory_get_peak_usage(true)),
    'growth_limit_bytes' => MAX_GROWTH_BYTES,
], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL);
