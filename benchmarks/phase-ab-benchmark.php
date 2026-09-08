<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Integrity\FileHasher;

$autoload = $argv[1] ?? dirname(__DIR__) . '/vendor/autoload.php';
$label = $argv[2] ?? 'current';

if (!is_file($autoload)) {
    throw new RuntimeException("Autoload file not found: {$autoload}");
}

require $autoload;

/** @return array{median_ms: float, p95_ms: float, min_ms: float, max_ms: float} */
function measure(callable $operation, int $iterations = 8, int $warmups = 2): array
{
    for ($i = 0; $i < $warmups; ++$i) {
        $operation();
    }

    $durations = [];
    for ($i = 0; $i < $iterations; ++$i) {
        $started = hrtime(true);
        $operation();
        $durations[] = (hrtime(true) - $started) / 1_000_000;
    }

    sort($durations, SORT_NUMERIC);
    $count = count($durations);
    $middle = intdiv($count, 2);
    $median = $count % 2 === 0
        ? ($durations[$middle - 1] + $durations[$middle]) / 2
        : $durations[$middle];
    $p95Index = min($count - 1, (int) ceil($count * 0.95) - 1);

    return [
        'median_ms' => round($median, 4),
        'p95_ms' => round($durations[$p95Index], 4),
        'min_ms' => round($durations[0], 4),
        'max_ms' => round($durations[$count - 1], 4),
    ];
}

$directory = sys_get_temp_dir() . '/epicrypt-phase-ab-' . bin2hex(random_bytes(5));
if (!mkdir($directory, 0700, true) && !is_dir($directory)) {
    throw new RuntimeException('Unable to create benchmark directory.');
}

$inputPath = $directory . '/input.bin';
$encryptedPath = $directory . '/encrypted.bin';
$outputPath = $directory . '/output.bin';
$payload = substr(str_repeat('Epicrypt-Phase-AB-0123456789abcdef', 32768), 0, 1024 * 1024);
file_put_contents($inputPath, $payload);

$key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
$options = new ProtectionOptions('phase-ab-benchmark', 'fixture=1mib');
$protector = new FileProtector();
$hasher = new FileHasher();

$results = [
    'label' => $label,
    'php' => PHP_VERSION,
    'os' => PHP_OS_FAMILY,
    'payload_bytes' => strlen($payload),
    'iterations' => 8,
    'pathwise_loaded' => class_exists('Infocyph\\Pathwise\\Storage\\StorageContext'),
    'supports_stream_api' => method_exists($protector, 'protectStream'),
    'path' => [],
];

foreach ([64 * 1024, 256 * 1024, 1024 * 1024] as $chunkSize) {
    $results['path']['file_roundtrip_' . $chunkSize] = measure(
        static function () use ($protector, $inputPath, $encryptedPath, $outputPath, $key, $options, $chunkSize): void {
            $protector->protect($inputPath, $encryptedPath, $key, $options, $chunkSize);
            $protector->unprotect($encryptedPath, $outputPath, $key, $options, $chunkSize);
        },
    );
}

$results['path']['sha256_1mib'] = measure(
    static fn(): string => $hasher->hash($inputPath),
    12,
    3,
);

if (!is_file($outputPath) || file_get_contents($outputPath) !== $payload) {
    throw new RuntimeException('Path benchmark round-trip produced incorrect output.');
}

if (method_exists($protector, 'protectStream') && method_exists($hasher, 'hashStream')) {
    $input = fopen('php://temp/maxmemory:2097152', 'w+b');
    $encrypted = fopen('php://temp/maxmemory:4194304', 'w+b');
    $output = fopen('php://temp/maxmemory:2097152', 'w+b');
    if (!is_resource($input) || !is_resource($encrypted) || !is_resource($output)) {
        throw new RuntimeException('Unable to create benchmark streams.');
    }

    fwrite($input, $payload);
    $results['stream'] = [];
    foreach ([64 * 1024, 256 * 1024, 1024 * 1024] as $chunkSize) {
        $results['stream']['file_roundtrip_' . $chunkSize] = measure(
            static function () use ($protector, $input, $encrypted, $output, $key, $options, $chunkSize): void {
                rewind($input);
                ftruncate($encrypted, 0);
                rewind($encrypted);
                ftruncate($output, 0);
                rewind($output);
                $protector->protectStream($input, $encrypted, $key, $options, $chunkSize);
                rewind($encrypted);
                $protector->unprotectStream($encrypted, $output, $key, $options, $chunkSize);
            },
        );
    }

    $results['stream']['sha256_1mib'] = measure(
        static function () use ($hasher, $input): string {
            rewind($input);

            return $hasher->hashStream($input);
        },
        12,
        3,
    );

    rewind($output);
    if (stream_get_contents($output) !== $payload) {
        throw new RuntimeException('Stream benchmark round-trip produced incorrect output.');
    }

    fclose($input);
    fclose($encrypted);
    fclose($output);
}

foreach ([$inputPath, $encryptedPath, $outputPath] as $path) {
    if (is_file($path)) {
        unlink($path);
    }
}
rmdir($directory);

fwrite(
    STDOUT,
    json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL,
);
