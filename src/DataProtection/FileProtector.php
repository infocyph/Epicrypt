<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class FileProtector
{
    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), StreamAlgorithm::XCHACHA20POLY1305, '');
        $stream->decrypt($inputPath, $outputPath, $chunkSize);
    }

    public function encrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): int {
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), StreamAlgorithm::XCHACHA20POLY1305, '');

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
