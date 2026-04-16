<?php

use Infocyph\Epicrypt\Integrity\FileHasher;
use Infocyph\Epicrypt\Integrity\StringHasher;
use Infocyph\Epicrypt\Integrity\Support\ContentFingerprinter;

it('hashes and verifies strings and files', function () {
    $stringHasher = new StringHasher('sha256');

    $digest = $stringHasher->hash('epicrypt-integrity');
    expect($stringHasher->verify('epicrypt-integrity', $digest))->toBeTrue();
    expect($stringHasher->verify('tampered', $digest))->toBeFalse();

    $tmpPath = tempnam(sys_get_temp_dir(), 'epicrypt-int-');
    file_put_contents($tmpPath, 'file-content');

    $fileHasher = new FileHasher('sha256');
    $fileDigest = $fileHasher->hash($tmpPath);

    expect($fileHasher->verify($tmpPath, $fileDigest))->toBeTrue();

    unlink($tmpPath);
});

it('creates stable content fingerprints', function () {
    $fingerprinter = new ContentFingerprinter();

    $fingerprintA = $fingerprinter->fingerprint('payload', ['b' => '2', 'a' => '1']);
    $fingerprintB = $fingerprinter->fingerprint('payload', ['a' => '1', 'b' => '2']);

    expect($fingerprintA)->toBe($fingerprintB);
});
