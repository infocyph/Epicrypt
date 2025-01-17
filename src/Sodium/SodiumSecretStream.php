<?php

namespace Infocyph\Epicrypt\Sodium;

use Infocyph\Epicrypt\Exceptions\FileAccessException;
use Infocyph\Pathwise\FileManager\SafeFileReader;
use Infocyph\Pathwise\FileManager\SafeFileWriter;
use InvalidArgumentException;

class SodiumSecretStream
{
    private string $key;
    private string $algorithm;
    private string $additionalData;

    public function __construct(string $key, string $algorithm = 'xchacha20poly1305', string $additionalData = '')
    {
        $this->key = $key;
        $this->algorithm = $algorithm;
        $this->additionalData = $additionalData;
    }

    public function encrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): int
    {
        $this->checkPrerequisite($inputPath);

        $fileWriter = new SafeFileWriter($outputPath, false);
        $writeChunkSize = match ($this->algorithm) {
            'xchacha20poly1305' => $this->encryptUsingSecretStream($inputPath, $fileWriter, $chunkSize),
            'xchacha20' => $this->encryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize),
        };

        $fileWriter->close();
        return $writeChunkSize;
    }

    public function decrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): void
    {
        $this->checkPrerequisite($inputPath);

        $fileWriter = new SafeFileWriter($outputPath, false);

        if ($this->algorithm === 'xchacha20poly1305') {
            $this->decryptUsingSecretStream($inputPath, $fileWriter, $chunkSize);
        } elseif ($this->algorithm === 'xchacha20') {
            $this->decryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize);
        }

        $fileWriter->close();
    }

    private function encryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        $fileWriter->binary($header);

        $fileReader = new SafeFileReader($inputPath);
        $fileReader = $fileReader->binary($chunkSize);

        $writeChunkSize = 0;

        foreach ($fileReader as $chunk) {
            if (is_null($chunk)) {
                continue;
            }

            $tag = $fileReader->valid()
                ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE
                : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

            $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $chunk,
                $this->additionalData,
                $tag,
            );
            $fileWriter->binary($encryptedChunk);
            $writeChunkSize = strlen($encryptedChunk);
        }

        sodium_memzero($state);
        return $writeChunkSize;
    }


    private function encryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        $nonce = random_bytes(SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES);
        $fileWriter->binary($nonce);

        $fileReader = new SafeFileReader($inputPath);
        $fileReader = $fileReader->binary($chunkSize);

        $writeChunkSize = 0;

        foreach ($fileReader as $chunk) {
            if (is_null($chunk)) {
                continue;
            }
            $encryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
            $fileWriter->binary($encryptedChunk);
            $writeChunkSize = strlen($encryptedChunk);
        }

        return $writeChunkSize;
    }

    private function decryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);

        // Read the header from the start of the file
        $header = $fileReader->binary(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES)->current();
        if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new \RuntimeException('Invalid header length.');
        }

        // Initialize the decryption state with the header
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);

        // Start reading the remaining file in chunks
        $fileReader = $fileReader->binary($chunkSize);

        foreach ($fileReader as $chunk) {
            if (is_null($chunk)) {
                continue; // Skip null chunks
            }

            [$data, $tag] = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $chunk, $this->additionalData);

            if (!$fileReader->valid() && $tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                throw new \RuntimeException('Incomplete or corrupted file detected during decryption.');
            }

            $fileWriter->binary($data);
        }

        sodium_memzero($state);
    }


    private function decryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);
        $fileReader = $fileReader->binary(SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES);

        $nonce = $fileReader->current();

        $fileReader = new SafeFileReader($inputPath);
        $fileReader = $fileReader->binary($chunkSize);

        foreach ($fileReader as $chunk) {
            $decryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
            $fileWriter->binary($decryptedChunk);
        }
    }

    private function checkPrerequisite(string $path): void
    {
        if (!in_array($this->algorithm, ['xchacha20poly1305', 'xchacha20'], true)) {
            throw new InvalidArgumentException('Unsupported algorithm: ' . $this->algorithm);
        }
        if (!file_exists($path) || !is_readable($path)) {
            throw new FileAccessException('Invalid input file: ' . $path);
        }
    }
}
