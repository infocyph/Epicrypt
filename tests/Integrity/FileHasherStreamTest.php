<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;

it('hashes and verifies caller-owned streams from their current position', function () {
    $stream = fopen('php://temp', 'w+b');
    fwrite($stream, 'skip|payload-to-hash');
    fseek($stream, 5);

    $hasher = new FileHasher(IntegrityAlgorithm::SHA256);
    $digest = $hasher->hashStream($stream);
    expect($digest)->toBe(hash('sha256', 'payload-to-hash'));

    rewind($stream);
    fseek($stream, 5);
    expect($hasher->verifyStream($stream, $digest))->toBeTrue();
});

it('supports bounded BLAKE2b digest lengths over streams', function () {
    $stream = fopen('php://temp', 'w+b');
    fwrite($stream, str_repeat('blake2b-stream', 1000));
    rewind($stream);

    $hasher = new FileHasher(IntegrityAlgorithm::BLAKE2B);
    $digest = $hasher->hashStream($stream, false, 32);

    expect(strlen($digest))->toBe(64);
    rewind($stream);
    expect($hasher->verifyStream($stream, $digest, false, 32))->toBeTrue();
});
