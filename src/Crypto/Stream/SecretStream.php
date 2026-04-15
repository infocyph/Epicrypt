<?php

namespace Infocyph\Epicrypt\Crypto\Stream;

use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Pathwise\FileManager\SafeFileReader;
use Infocyph\Pathwise\FileManager\SafeFileWriter;
use InvalidArgumentException;
use RuntimeException;

final readonly class SecretStream
{
    private const array SUPPORTED_ALGORITHMS = ['xchacha20poly1305', 'xchacha20'];

    private string $algorithm;

    public function __construct(
        private string $key,
        string $algorithm = 'xchacha20poly1305',
        private string $additionalData = '',
    ) {
        $this->assertSupportedAlgorithm($algorithm);
        $this->algorithm = $algorithm;
    }

    public function decrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): void
    {
        $this->checkReadableInput($inputPath);

        $fileWriter = new SafeFileWriter($outputPath, false);

        try {
            if ($this->algorithm === 'xchacha20poly1305') {
                $this->decryptUsingSecretStream($inputPath, $fileWriter, $chunkSize);
            } else {
                $this->decryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize);
            }
        } catch (RuntimeException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        } finally {
            $fileWriter->close();
        }
    }

    public function encrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): int
    {
        $this->checkReadableInput($inputPath);

        $fileWriter = new SafeFileWriter($outputPath, false);

        try {
            return match ($this->algorithm) {
                'xchacha20poly1305' => $this->encryptUsingSecretStream($inputPath, $fileWriter, $chunkSize),
                'xchacha20' => $this->encryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize),
            };
        } catch (RuntimeException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        } finally {
            $fileWriter->close();
        }
    }

    private function assertSupportedAlgorithm(string $algorithm): void
    {
        if (! in_array($algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new InvalidArgumentException('Unsupported algorithm: ' . $algorithm);
        }
    }

    private function checkReadableInput(string $path): void
    {
        if (! file_exists($path) || ! is_readable($path)) {
            throw new FileAccessException('Invalid input file: ' . $path);
        }
    }

    private function decryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);

        try {
            $nonce = $fileReader->binary(SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES)->current();
            if (! is_string($nonce) || strlen($nonce) !== SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES) {
                throw new RuntimeException('Invalid nonce length.');
            }

            $chunkIterator = $fileReader->binary($chunkSize);

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }

                $decryptedChunk = sodium_crypto_stream_xchacha20_xor((string) $chunk, (string) $nonce, $this->key);
                $fileWriter->binary($decryptedChunk);
                sodium_increment($nonce);
            }
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function decryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);

        try {
            $header = $fileReader->binary(SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES)->current();
            if (! is_string($header) || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                throw new RuntimeException('Invalid secret stream header.');
            }

            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
            $isFinalTagSeen = false;
            $cipherChunkSize = $chunkSize + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
            $chunkIterator = $fileReader->binary($cipherChunkSize);

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }

                $decryptedFrame = sodium_crypto_secretstream_xchacha20poly1305_pull(
                    $state,
                    (string) $chunk,
                    $this->additionalData,
                );

                if ($decryptedFrame === false) {
                    throw new RuntimeException('Failed to decrypt secret stream frame.');
                }

                [$data, $tag] = $decryptedFrame;
                $fileWriter->binary($data);

                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $isFinalTagSeen = true;
                    break;
                }
            }

            if (! $isFinalTagSeen) {
                throw new RuntimeException('Incomplete or corrupted file detected during decryption.');
            }

            sodium_memzero($state);
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function encryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        $nonce = random_bytes(SODIUM_CRYPTO_STREAM_XCHACHA20_NONCEBYTES);
        $fileWriter->binary($nonce);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $chunkIterator = $fileReader->binary($chunkSize);
            $writeChunkSize = 0;

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }

                $encryptedChunk = sodium_crypto_stream_xchacha20_xor((string) $chunk, (string) $nonce, $this->key);
                $fileWriter->binary($encryptedChunk);
                $writeChunkSize = strlen($encryptedChunk);
                sodium_increment($nonce);
            }

            return $writeChunkSize;
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function encryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        $fileWriter->binary($header);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $chunkIterator = $fileReader->binary($chunkSize);
            $writeChunkSize = 0;
            $bufferedChunk = null;

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }

                if ($bufferedChunk === null) {
                    $bufferedChunk = $chunk;
                    continue;
                }

                $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $state,
                    (string) $bufferedChunk,
                    $this->additionalData,
                    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                );

                $fileWriter->binary($encryptedChunk);
                $writeChunkSize = strlen($encryptedChunk);
                $bufferedChunk = $chunk;
            }

            $finalChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $bufferedChunk ?? '',
                $this->additionalData,
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            );

            $fileWriter->binary($finalChunk);
            $writeChunkSize = strlen($finalChunk);
            sodium_memzero($state);

            return $writeChunkSize;
        } finally {
            $fileReader->releaseLock();
        }
    }
}
