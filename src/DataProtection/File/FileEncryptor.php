<?php

namespace Infocyph\Epicrypt\DataProtection\File;

use Infocyph\Epicrypt\Crypto\Stream\FileEncryptor as StreamFileEncryptor;

final readonly class FileEncryptor
{
    public function __construct(
        private StreamFileEncryptor $encryptor = new StreamFileEncryptor(),
    ) {}

    public function encrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): int {
        return $this->encryptor->encrypt($inputPath, $outputPath, $key, 'xchacha20poly1305', '', $chunkSize, $keyIsBinary);
    }
}
