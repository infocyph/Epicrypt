<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class FileCipher
{
    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        string $algorithm = 'xchacha20poly1305',
        string $additionalData = '',
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->assertReadableFile($inputPath);
        $decodedKey = $this->decodeKey($key, $keyIsBinary);
        $stream = new SecretStream($decodedKey, $algorithm, $additionalData);
        $stream->decrypt($inputPath, $outputPath, $chunkSize);
    }
    public function encrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        string $algorithm = 'xchacha20poly1305',
        string $additionalData = '',
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): int {
        $this->assertReadableFile($inputPath);
        $decodedKey = $this->decodeKey($key, $keyIsBinary);
        $stream = new SecretStream($decodedKey, $algorithm, $additionalData);

        return $stream->encrypt($inputPath, $outputPath, $chunkSize);
    }

    private function assertReadableFile(string $path): void
    {
        if (! file_exists($path) || ! is_readable($path)) {
            throw new FileAccessException('Input file is not readable: ' . $path);
        }
    }

    private function decodeKey(string $key, bool $keyIsBinary): string
    {
        $decodedKey = $keyIsBinary ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new InvalidKeyException('Stream key must be 32 bytes.');
        }

        return $decodedKey;
    }
}
