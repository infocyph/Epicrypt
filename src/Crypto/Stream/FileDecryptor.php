<?php

namespace Infocyph\Epicrypt\Crypto\Stream;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class FileDecryptor
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
        if (! file_exists($inputPath) || ! is_readable($inputPath)) {
            throw new FileAccessException('Input file is not readable: ' . $inputPath);
        }

        $decodedKey = $keyIsBinary ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new InvalidKeyException('Stream key must be 32 bytes.');
        }

        $stream = new SecretStream($decodedKey, $algorithm, $additionalData);
        $stream->decrypt($inputPath, $outputPath, $chunkSize);
    }
}
