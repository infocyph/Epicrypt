<?php

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\FileCipher;

final readonly class FileProtector
{
    public function __construct(
        private FileCipher $cipher = new FileCipher(),
    ) {}

    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->cipher->decrypt($inputPath, $outputPath, $key, 'xchacha20poly1305', '', $chunkSize, $keyIsBinary);
    }

    public function encrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): int {
        return $this->cipher->encrypt($inputPath, $outputPath, $key, 'xchacha20poly1305', '', $chunkSize, $keyIsBinary);
    }
}
