<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;

const EPICRYPT_V2_FILE_FIXTURE_KEY = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const EPICRYPT_V2_FILE_FIXTURE = 'ZXAyLmV5SjJJam95TENKa2IyMWhhVzRpT2lKbWFXeGxJaXdpWVd4bklqb2llR05vWVdOb1lUSXdMWEJ2YkhreE16QTFMWE5sWTNKbGRITjBjbVZoYlNJc0ltdHBaQ0k2SW1acGVIUjFjbVV0YTJWNUlpd2ljSFZ5Y0c5elpTSTZJbkJvWVhObExXRWlMQ0pqY21WaGRHVmtYMkYwSWpveE56QXdNREF3TURBd0xDSmhZV1FpT2lKa1IxWjFXVmMxTUZCWVFtOVpXRTVzVEZkRkluMAq/HXnKRHjCTA4LHHdXH6IrMQOwbm6mhfgvSNSYuXPeBQIWok2KjSBJL0etPhjxf2teu+Q+rmaHprL98mD6CdROpGo4jkzU+8EPb0I+O+24QEsnJYytVTE0K1fLUQCvFK+T5xt8BHg56B9YWW4WN/g=';

it('roundtrips SecretStream directly through caller-owned PHP streams', function () {
    $key = random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES);
    $plaintext = random_bytes(150_000);
    $input = fopen('php://temp', 'w+b');
    $encrypted = fopen('php://temp', 'w+b');
    $output = fopen('php://temp', 'w+b');

    fwrite($input, $plaintext);
    rewind($input);
    $stream = new SecretStream($key, 'stream-aad');
    $written = $stream->encryptStream($input, $encrypted, 16 * 1024);
    expect($written)->toBeGreaterThan(strlen($plaintext));

    rewind($encrypted);
    $stream->decryptStream($encrypted, $output, 16 * 1024);
    rewind($output);

    expect(stream_get_contents($output))->toBe($plaintext);
});

it('roundtrips FileProtector through caller-owned streams without Pathwise state', function () {
    $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $options = new ProtectionOptions('stream-backup', 'tenant=stream', 'current');
    $plaintext = str_repeat('stream-protection-', 10_000);
    $input = fopen('php://temp', 'w+b');
    $encrypted = fopen('php://temp', 'w+b');
    $output = fopen('php://temp', 'w+b');
    fwrite($input, $plaintext);
    rewind($input);

    $protector = new FileProtector();
    $protected = $protector->protectStream($input, $encrypted, $key, $options, 32 * 1024);
    expect($protected->domain)->toBe('file')
        ->and($protected->purpose)->toBe('stream-backup')
        ->and($protected->keyId)->toBe('current');

    rewind($encrypted);
    $unprotected = $protector->unprotectStream($encrypted, $output, $key, $options, 32 * 1024);
    rewind($output);

    expect(stream_get_contents($output))->toBe($plaintext)
        ->and($unprotected->keyId)->toBe('current');
});

it('decrypts the frozen Epicrypt 2.x protected-file fixture', function () {
    $fixture = base64_decode(EPICRYPT_V2_FILE_FIXTURE, true);
    expect($fixture)->toBeString()
        ->and(hash('sha256', $fixture))->toBe('92e26afe6c140fc4c605022a59e67a8328e894219afddd91091a80e2b942e275');

    $input = fopen('php://temp', 'w+b');
    $output = fopen('php://temp', 'w+b');
    fwrite($input, $fixture);
    rewind($input);

    $result = new FileProtector()->unprotectStream(
        $input,
        $output,
        EPICRYPT_V2_FILE_FIXTURE_KEY,
        new ProtectionOptions('phase-a', 'tenant=phase-a', 'fixture-key'),
        16,
    );
    rewind($output);

    expect(stream_get_contents($output))->toBe("Epicrypt 2.x protected file fixture\n")
        ->and($result->createdAt)->toBe(1_700_000_000)
        ->and($result->keyId)->toBe('fixture-key');
});
