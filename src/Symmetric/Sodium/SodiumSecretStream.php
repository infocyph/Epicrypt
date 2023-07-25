<?php

namespace AbmmHasan\SafeGuard\Symmetric\Sodium;

use AbmmHasan\SafeGuard\Misc\ReadFile;
use SodiumException;

class SodiumSecretStream
{
    /**
     * @param string $key
     * @throws SodiumException
     */
    public function __construct(
        private string $key,
    ) {
        // ToDo: Still incomplete. WIP!
    }

    public function encryptFile(string $inputPath, string $outputPath, int $blockSize = 1024)
    {
        if (!file_exists($inputPath) || !is_readable($inputPath)) {
            throw new Exception("Invalid file path!");
        }
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        if (file_put_contents($outputPath, $header) === false) {
            throw new Exception('Invalid output file path!');
        }
        $fileObject = new ReadFile($inputPath, 'rb');
        foreach ($fileObject->binary($blockSize) as $index => $chunk) {
            $writeChunkSize[] = file_put_contents(
                $outputPath,
                sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk),
                FILE_APPEND | LOCK_EX
            );
        }
        sodium_memzero($state);
        return $writeChunkSize;
    }

    public function decryptFile(string $inputPath, string $outputPath, int $blockSize = 1024)
    {
        if (!file_exists($inputPath) || !is_readable($inputPath)) {
            throw new Exception("Invalid file path!");
        }
        if (file_put_contents($outputPath, '') === false) {
            throw new Exception('Invalid output file path!');
        }
        $fileObject = new ReadFile($inputPath, 'rb');
        $header = $fileObject->set('fread', 24);
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
        foreach ($fileObject->binary($blockSize) as $index => $chunk) {
            $writeChunkSize[] = file_put_contents(
                $outputPath,
                [$data, $tag] = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk),
                FILE_APPEND | LOCK_EX
            );
        }
        sodium_memzero($state);
    }
}