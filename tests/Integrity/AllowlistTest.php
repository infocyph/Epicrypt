<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Exception\Integrity\HashingException;
use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;
use Infocyph\Epicrypt\Integrity\StringHasher;
use Infocyph\Pathwise\Storage\StorageContext;

it('supports only the security integrity allowlist', function (IntegrityAlgorithm $algorithm) {
    $hasher = new StringHasher($algorithm);
    $digest = $hasher->hash('content');
    expect($hasher->verify('content', $digest))->toBeTrue()
        ->and($hasher->verify('changed', $digest))->toBeFalse();
})->with(IntegrityAlgorithm::cases());

it('hashes files with allowlisted algorithms', function () {
    $path = tempnam(sys_get_temp_dir(), 'epicrypt-hash-');
    file_put_contents($path, 'file content');
    $hasher = new FileHasher(IntegrityAlgorithm::SHA512);
    expect($hasher->verify($path, $hasher->hash($path)))->toBeTrue();
});

it('validates BLAKE2b output lengths and treats malformed digests as mismatches', function () {
    $hasher = new StringHasher(IntegrityAlgorithm::BLAKE2B);
    expect(strlen($hasher->hash('content', length: 16)))->toBe(32)
        ->and(strlen($hasher->hash('content', length: 64)))->toBe(128)
        ->and($hasher->verify('content', 'not-hex'))->toBeFalse()
        ->and($hasher->verify('content', str_repeat('0', 127), length: 64))->toBeFalse()
        ->and(fn () => $hasher->hash('content', length: 15))->toThrow(HashingException::class)
        ->and(fn () => $hasher->hash('content', length: 65))->toThrow(HashingException::class)
        ->and(fn () => new StringHasher()->hash('content', length: 32))->toThrow(HashingException::class);
});

it('streams large local and Pathwise context files without global mounts', function () {
    $directory = sys_get_temp_dir().'/epicrypt-pathwise-hash-'.bin2hex(random_bytes(6));
    mkdir($directory, recursive: true);
    $content = str_repeat('streamed-content-', 100_000);
    file_put_contents($directory.'/artifact.bin', $content);
    $hasher = new FileHasher(IntegrityAlgorithm::SHA384);
    $context = new StorageContext(['integrity-test' => ['driver' => 'local', 'root' => $directory]], 'integrity-test');
    $filesystem = $context->filesystem();

    $artifact = $filesystem->readStream('artifact.bin');
    try {
        expect($hasher->hash($directory.'/artifact.bin'))->toBe(hash('sha384', $content))
            ->and($hasher->hashStream($artifact))->toBe(hash('sha384', $content));
    } finally {
        fclose($artifact);
    }

    $filesystem->write('mounted-only.bin', 'mounted content');
    $mountedOnly = $filesystem->readStream('mounted-only.bin');
    try {
        expect($hasher->verifyStream($mountedOnly, hash('sha384', 'mounted content')))->toBeTrue();
    } finally {
        fclose($mountedOnly);
    }
});
