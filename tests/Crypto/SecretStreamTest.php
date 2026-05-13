<?php

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

it('rejects direct secret stream construction with invalid key length', function () {
    expect(fn() => new SecretStream('short-key'))->toThrow(InvalidKeyException::class);
});

it('requires explicit opt-in for unauthenticated stream mode', function () {
    $key = random_bytes(SODIUM_CRYPTO_STREAM_XCHACHA20_KEYBYTES);

    expect(
        fn() => new SecretStream($key, StreamAlgorithm::UNAUTHENTICATED_XCHACHA20),
    )->toThrow(ConfigurationException::class);

    expect(
        new SecretStream($key, StreamAlgorithm::UNAUTHENTICATED_XCHACHA20, '', true),
    )->toBeInstanceOf(SecretStream::class);
});

it('returns total bytes written for single-chunk secret stream encryption', function () {
    $directory = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-secretstream-'.bin2hex(random_bytes(6));
    mkdir($directory);

    $inputPath = $directory.DIRECTORY_SEPARATOR.'plain.txt';
    $encryptedPath = $directory.DIRECTORY_SEPARATOR.'encrypted.bin';
    $decryptedPath = $directory.DIRECTORY_SEPARATOR.'decrypted.txt';
    file_put_contents($inputPath, 'small payload');

    try {
        $stream = new SecretStream(random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES));
        $written = $stream->encrypt($inputPath, $encryptedPath, 8192);
        $stream->decrypt($encryptedPath, $decryptedPath, 8192);

        expect($written)->toBe(filesize($encryptedPath));
        expect(file_get_contents($decryptedPath))->toBe('small payload');
    } finally {
        cleanupSecretStreamTempDirectory($directory);
    }
});

it('returns total bytes written for multi-chunk secret stream encryption', function () {
    $directory = sys_get_temp_dir().DIRECTORY_SEPARATOR.'epicrypt-secretstream-'.bin2hex(random_bytes(6));
    mkdir($directory);

    $inputPath = $directory.DIRECTORY_SEPARATOR.'plain.txt';
    $encryptedPath = $directory.DIRECTORY_SEPARATOR.'encrypted.bin';
    $decryptedPath = $directory.DIRECTORY_SEPARATOR.'decrypted.txt';
    $content = str_repeat('chunked-stream-data-', 64);
    file_put_contents($inputPath, $content);

    try {
        $stream = new SecretStream(random_bytes(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES));
        $written = $stream->encrypt($inputPath, $encryptedPath, 17);
        $stream->decrypt($encryptedPath, $decryptedPath, 17);

        expect($written)->toBe(filesize($encryptedPath));
        expect(file_get_contents($decryptedPath))->toBe($content);
    } finally {
        cleanupSecretStreamTempDirectory($directory);
    }
});

function cleanupSecretStreamTempDirectory(string $directory): void
{
    if (!is_dir($directory)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST,
    );

    foreach ($iterator as $entry) {
        if ($entry->isDir()) {
            $path = $entry->getPathname();
            if (is_dir($path)) {
                rmdir($path);
            }

            continue;
        }

        $path = $entry->getPathname();
        if (file_exists($path)) {
            unlink($path);
        }
    }

    // Keep root temp directory in warning-free mode; CI temp cleanup handles it.
}
