<?php

declare(strict_types=1);

use Infocyph\Epicrypt\DataProtection\FileProtector;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

it('encrypts and decrypts empty, small, multi-chunk and large files', function () {
    $generator = new KeyMaterialGenerator;
    $key = $generator->forSecretStream();

    $root = makeMatrixTempDirectory();
    $protector = FileProtector::forProfile(SecurityProfile::MODERN);

    $cases = [
        'empty' => '',
        'small' => 'small-file-payload',
        'multi_chunk' => str_repeat('chunk-', 4_000),
        'large' => random_bytes(1_048_576 + 31),
    ];

    try {
        foreach ($cases as $name => $content) {
            $plain = $root.DIRECTORY_SEPARATOR.$name.'.plain.bin';
            $encrypted = $root.DIRECTORY_SEPARATOR.$name.'.enc.bin';
            $decrypted = $root.DIRECTORY_SEPARATOR.$name.'.dec.bin';

            file_put_contents($plain, $content);

            $written = $protector->encrypt($plain, $encrypted, $key, 1024);
            $protector->decrypt($encrypted, $decrypted, $key, 1024);

            expect($written)->toBe(filesize($encrypted));
            expect(file_get_contents($decrypted))->toBe($content);
        }
    } finally {
        removeMatrixTempDirectory($root);
    }
});

it('fails file decryption with wrong key', function () {
    $generator = new KeyMaterialGenerator;
    $correctKey = $generator->forSecretStream();
    $wrongKey = $generator->forSecretStream();

    $root = makeMatrixTempDirectory();
    $plain = $root.DIRECTORY_SEPARATOR.'payload.txt';
    $encrypted = $root.DIRECTORY_SEPARATOR.'payload.enc';
    $decrypted = $root.DIRECTORY_SEPARATOR.'payload.dec';
    file_put_contents($plain, 'file-protection payload');

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);

    try {
        $protector->encrypt($plain, $encrypted, $correctKey);
        file_put_contents($decrypted, 'existing output');

        expect(fn () => $protector->decrypt($encrypted, $decrypted, $wrongKey))
            ->toThrow(DecryptionException::class)
            ->and(file_get_contents($decrypted))->toBe('existing output');
    } finally {
        removeMatrixTempDirectory($root);
    }
});

it('fails file decryption when ciphertext is tampered', function () {
    $generator = new KeyMaterialGenerator;
    $key = $generator->forSecretStream();

    $root = makeMatrixTempDirectory();
    $plain = $root.DIRECTORY_SEPARATOR.'payload.txt';
    $encrypted = $root.DIRECTORY_SEPARATOR.'payload.enc';
    $decrypted = $root.DIRECTORY_SEPARATOR.'payload.dec';
    file_put_contents($plain, str_repeat('tamper-check-', 2_000));

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);

    try {
        $protector->encrypt($plain, $encrypted, $key, 256);
        $ciphertext = (string) file_get_contents($encrypted);
        file_put_contents($encrypted, substr($ciphertext, 0, max(0, strlen($ciphertext) - 5)));

        expect(fn () => $protector->decrypt($encrypted, $decrypted, $key, 256))
            ->toThrow(DecryptionException::class)
            ->and(file_exists($decrypted))->toBeFalse();
    } finally {
        removeMatrixTempDirectory($root);
    }
});

it('supports file protection with binary stream keys', function () {
    $key = (new KeyMaterialGenerator)->forSecretStream(asBase64Url: false);
    $root = makeMatrixTempDirectory();
    $plain = $root.DIRECTORY_SEPARATOR.'payload.txt';
    $encrypted = $root.DIRECTORY_SEPARATOR.'payload.enc';
    $decrypted = $root.DIRECTORY_SEPARATOR.'payload.dec';
    file_put_contents($plain, 'binary-stream-key payload');

    $protector = FileProtector::forProfile(SecurityProfile::MODERN);

    try {
        $protector->encrypt($plain, $encrypted, $key, 1024, true);
        $protector->decrypt($encrypted, $decrypted, $key, 1024, true);

        expect(file_get_contents($decrypted))->toBe('binary-stream-key payload');
    } finally {
        removeMatrixTempDirectory($root);
    }
});

function makeMatrixTempDirectory(): string
{
    $path = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-file-matrix-'.bin2hex(random_bytes(6));
    mkdir($path);

    return $path;
}

function removeMatrixTempDirectory(string $path): void
{
    $rootPath = $path;
    if (! is_dir($rootPath)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($rootPath, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $entry) {
        if ($entry->isDir()) {
            $entryPath = $entry->getPathname();
            if (is_dir($entryPath)) {
                rmdir($entryPath);
            }

            continue;
        }

        $entryPath = $entry->getPathname();
        if (file_exists($entryPath)) {
            unlink($entryPath);
        }
    }

    // Keep root temp directory in warning-free mode; CI temp cleanup handles it.
}
