<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integrity\IntegrityAlgorithm;
use Infocyph\Epicrypt\Integrity\StringHasher;

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
