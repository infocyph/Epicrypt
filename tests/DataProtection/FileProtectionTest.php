<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\DataProtection\ProtectionOptions;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\FileAccessException;

it('roundtrips empty and multi-frame files with authenticated framing', function (string $content) {
    $directory = sys_get_temp_dir() . '/epicrypt-' . bin2hex(random_bytes(6));
    mkdir($directory);
    $input = $directory . '/input';
    $encrypted = $directory . '/encrypted';
    $output = $directory . '/output';
    file_put_contents($input, $content);
    $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $options = new ProtectionOptions('backup', 'tenant=1');
    $protector = new FileProtector();

    $protector->protect($input, $encrypted, $key, $options, 64 * 1024);
    file_put_contents($output, 'existing destination');
    $protector->unprotect($encrypted, $output, $key, $options, 64 * 1024);

    expect(file_get_contents($output))->toBe($content);
})->with(['empty' => '', 'large' => str_repeat('Epicrypt2', 20_000)]);

it('rejects corruption, truncation, trailing data, and source destination collision', function () {
    $directory = sys_get_temp_dir() . '/epicrypt-' . bin2hex(random_bytes(6));
    mkdir($directory);
    $input = $directory . '/input';
    $encrypted = $directory . '/encrypted';
    $output = $directory . '/output';
    file_put_contents($input, random_bytes(200_000));
    $key = sodium_bin2base64(random_bytes(32), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    $options = new ProtectionOptions('archive');
    $protector = new FileProtector();
    $protector->protect($input, $encrypted, $key, $options, 64 * 1024);
    $original = file_get_contents($encrypted);
    $prefixLength = strpos($original, "\n") + 1;
    $finalFrameLength = (200_000 % (64 * 1024)) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
    $finalFrame = substr($original, -$finalFrameLength);

    $invalidPayloads = [
        'trailing bytes' => $original . 'x',
        'duplicate final frame' => $original . $finalFrame,
        'missing final frame' => substr($original, 0, -$finalFrameLength),
        'truncated header' => substr($original, 0, $prefixLength + 10),
        'truncated frame' => substr($original, 0, -1),
        'corrupted frame' => substr_replace($original, 'x', -20, 1),
    ];
    foreach ($invalidPayloads as $invalid) {
        file_put_contents($encrypted, $invalid);
        file_put_contents($output, 'preserve me');
        expect(fn() => $protector->unprotect($encrypted, $output, $key, $options, 64 * 1024))
            ->toThrow(DecryptionException::class)
            ->and(file_get_contents($output))->toBe('preserve me');
    }

    file_put_contents($encrypted, $original);
    file_put_contents($output, 'preserve me');
    expect(fn() => $protector->unprotect(
        $encrypted,
        $output,
        $key,
        new ProtectionOptions('archive', keyId: 'wrong-key'),
        64 * 1024,
    ))->toThrow(DecryptionException::class)
        ->and(file_get_contents($output))->toBe('preserve me');

    expect(fn() => new SecretStream(random_bytes(32))->encrypt($input, $input))
        ->toThrow(FileAccessException::class);
});
