<?php

namespace Infocyph\Epicrypt\DataProtection\File;

use Infocyph\Epicrypt\Crypto\Stream\FileDecryptor as StreamFileDecryptor;

final readonly class FileDecryptor
{
    public function __construct(
        private StreamFileDecryptor $decryptor = new StreamFileDecryptor(),
    ) {}

    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->decryptor->decrypt($inputPath, $outputPath, $key, 'xchacha20poly1305', '', $chunkSize, $keyIsBinary);
    }
}
