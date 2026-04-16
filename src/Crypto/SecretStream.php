<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Pathwise\FileManager\SafeFileReader;
use Infocyph\Pathwise\FileManager\SafeFileWriter;
use RuntimeException;

final readonly class SecretStream
{
    public function __construct(private string $key, private StreamAlgorithm $algorithm = StreamAlgorithm::XCHACHA20POLY1305, private string $additionalData = '') {}

    public function decrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): void
    {
        $this->checkReadableInput($inputPath);

        $fileWriter = new SafeFileWriter($outputPath, false);

        try {
            if ($this->algorithm->usesSecretStream()) {
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
            if ($this->algorithm->usesSecretStream()) {
                return $this->encryptUsingSecretStream($inputPath, $fileWriter, $chunkSize);
            }

            return $this->encryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize);
        } catch (RuntimeException $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        } finally {
            $fileWriter->close();
        }
    }

    private function checkReadableInput(string $path): void
    {
        if (!file_exists($path) || !is_readable($path)) {
            throw new FileAccessException('Invalid input file: ' . $path);
        }
    }

    private function decryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);

        try {
            $nonce = $fileReader->binary($this->algorithm->prefixLength())->current();
            if (!is_string($nonce) || strlen($nonce) !== $this->algorithm->prefixLength()) {
                throw new RuntimeException('Invalid nonce length.');
            }

            $chunkIterator = $fileReader->binary($chunkSize);

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }
                if (!is_string($chunk)) {
                    throw new RuntimeException('Invalid plaintext chunk encountered.');
                }

                $decryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
                $this->writeBinary($fileWriter, $decryptedChunk);
                $nonce = $this->incrementNonce($nonce);
            }
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function decryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): void
    {
        $fileReader = new SafeFileReader($inputPath);

        try {
            $header = $fileReader->binary($this->algorithm->prefixLength())->current();
            if (!is_string($header) || strlen($header) !== $this->algorithm->prefixLength()) {
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
                if (!is_string($chunk)) {
                    throw new RuntimeException('Invalid ciphertext chunk encountered.');
                }

                $decryptedFrame = sodium_crypto_secretstream_xchacha20poly1305_pull(
                    $state,
                    $chunk,
                    $this->additionalData,
                );

                if ($decryptedFrame === false) {
                    throw new RuntimeException('Failed to decrypt secret stream frame.');
                }

                [$data, $tag] = $decryptedFrame;
                if (!is_string($data) || !is_int($tag)) {
                    throw new RuntimeException('Invalid secret stream frame.');
                }

                $this->writeBinary($fileWriter, $data);

                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    $isFinalTagSeen = true;

                    break;
                }
            }

            if (!$isFinalTagSeen) {
                throw new RuntimeException('Incomplete or corrupted file detected during decryption.');
            }

            sodium_memzero($state);
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function encryptUsingCryptoStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        $nonce = random_bytes($this->algorithm->prefixLength());
        $this->writeBinary($fileWriter, $nonce);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $chunkIterator = $fileReader->binary($chunkSize);
            $writeChunkSize = 0;

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }
                if (!is_string($chunk)) {
                    throw new RuntimeException('Invalid plaintext chunk encountered.');
                }

                $encryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
                $this->writeBinary($fileWriter, $encryptedChunk);
                $writeChunkSize = strlen($encryptedChunk);
                $nonce = $this->incrementNonce($nonce);
            }

            return $writeChunkSize;
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function encryptUsingSecretStream(string $inputPath, SafeFileWriter $fileWriter, int $chunkSize): int
    {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        if (!is_string($state) || !is_string($header)) {
            throw new RuntimeException('Unable to initialize secret stream push state.');
        }

        $this->writeBinary($fileWriter, $header);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $chunkIterator = $fileReader->binary($chunkSize);
            $writeChunkSize = 0;
            /** @var string|null $bufferedChunk */
            $bufferedChunk = null;

            foreach ($chunkIterator as $chunk) {
                if ($chunk === null || $chunk === '') {
                    continue;
                }
                if (!is_string($chunk)) {
                    throw new RuntimeException('Invalid plaintext chunk encountered.');
                }

                if ($bufferedChunk === null) {
                    $bufferedChunk = $chunk;

                    continue;
                }

                $encryptedChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $state,
                    $bufferedChunk,
                    $this->additionalData,
                    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                );

                $this->writeBinary($fileWriter, $encryptedChunk);
                $writeChunkSize = strlen($encryptedChunk);
                $bufferedChunk = $chunk;
            }

            $finalChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $bufferedChunk ?? '',
                $this->additionalData,
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            );

            $this->writeBinary($fileWriter, $finalChunk);
            $writeChunkSize = strlen($finalChunk);
            sodium_memzero($state);

            return $writeChunkSize;
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function incrementNonce(string $nonce): string
    {
        $length = strlen($nonce);
        if ($length === 0) {
            throw new RuntimeException('Nonce must not be empty.');
        }

        $bytes = str_split($nonce);

        for ($index = $length - 1; $index >= 0; --$index) {
            $next = (ord($bytes[$index]) + 1) & 0xff;
            $bytes[$index] = chr($next);

            if ($next !== 0) {
                break;
            }
        }

        return implode('', $bytes);
    }

    private function writeBinary(SafeFileWriter $fileWriter, string $data): void
    {
        $written = $fileWriter->__call('binary', [$data]);
        if ($written === false) {
            throw new RuntimeException('Failed to write output chunk.');
        }
    }
}
