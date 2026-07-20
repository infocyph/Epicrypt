<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Pathwise\FileManager\SafeFileReader;
use Infocyph\Pathwise\FileManager\SafeFileWriter;
use RuntimeException;

final readonly class SecretStream
{
    private const int MAX_CHUNK_SIZE = 16 * 1024 * 1024;

    public function __construct(
        private string $key,
        private StreamAlgorithm $algorithm = StreamAlgorithm::XCHACHA20POLY1305,
        private string $additionalData = '',
        private bool $allowUnauthenticatedStream = false,
    ) {
        if (strlen($this->key) !== $this->algorithm->keyLength()) {
            throw new InvalidKeyException(sprintf('Stream key must be %d bytes.', $this->algorithm->keyLength()));
        }

        if ($this->algorithm === StreamAlgorithm::UNAUTHENTICATED_XCHACHA20 && !$this->allowUnauthenticatedStream) {
            throw new ConfigurationException('Unauthenticated stream encryption must be explicitly enabled.');
        }
    }

    public function decrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): void
    {
        $this->assertValidChunkSize($chunkSize);
        $this->checkReadableInput($inputPath);

        try {
            $this->writeSafely($outputPath, function (SafeFileWriter $fileWriter) use ($inputPath, $chunkSize): void {
                if ($this->algorithm->usesSecretStream()) {
                    $this->decryptUsingSecretStream($inputPath, $fileWriter, $chunkSize);

                    return;
                }

                $this->decryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize);
            });
        } catch (\Exception $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }

    public function encrypt(string $inputPath, string $outputPath, int $chunkSize = 8192): int
    {
        $this->assertValidChunkSize($chunkSize);
        $this->checkReadableInput($inputPath);

        try {
            return $this->writeSafely(
                $outputPath,
                fn(SafeFileWriter $fileWriter): int => $this->algorithm->usesSecretStream()
                    ? $this->encryptUsingSecretStream($inputPath, $fileWriter, $chunkSize)
                    : $this->encryptUsingCryptoStream($inputPath, $fileWriter, $chunkSize),
            );
        } catch (\Exception $e) {
            throw new EncryptionException($e->getMessage(), 0, $e);
        }
    }

    private function assertValidChunkSize(int $chunkSize): void
    {
        if ($chunkSize < 1 || $chunkSize > self::MAX_CHUNK_SIZE) {
            throw new ConfigurationException(sprintf(
                'Chunk size must be between 1 and %d bytes.',
                self::MAX_CHUNK_SIZE,
            ));
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

            $this->forEachChunk($fileReader, $chunkSize, 'plaintext', function (string $chunk) use ($fileWriter, &$nonce): void {
                $decryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
                $this->writeBinary($fileWriter, $decryptedChunk);
                $nonce = $this->incrementNonce($nonce);
            });
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
                $chunk = $this->normalizeChunk($chunk, 'ciphertext');
                if ($chunk === null) {
                    continue;
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
        $bytesWritten = $this->writeBinary($fileWriter, $nonce);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $this->forEachChunk($fileReader, $chunkSize, 'plaintext', function (string $chunk) use ($fileWriter, &$nonce, &$bytesWritten): void {
                $encryptedChunk = sodium_crypto_stream_xchacha20_xor($chunk, $nonce, $this->key);
                $bytesWritten += $this->writeBinary($fileWriter, $encryptedChunk);
                $nonce = $this->incrementNonce($nonce);
            });

            return $bytesWritten;
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

        $bytesWritten = $this->writeBinary($fileWriter, $header);

        $fileReader = new SafeFileReader($inputPath);

        try {
            $chunkIterator = $fileReader->binary($chunkSize);
            /** @var string|null $bufferedChunk */
            $bufferedChunk = null;

            foreach ($chunkIterator as $chunk) {
                $chunk = $this->normalizeChunk($chunk, 'plaintext');
                if ($chunk === null) {
                    continue;
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

                $bytesWritten += $this->writeBinary($fileWriter, $encryptedChunk);
                $bufferedChunk = $chunk;
            }

            $finalChunk = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $bufferedChunk ?? '',
                $this->additionalData,
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            );

            $bytesWritten += $this->writeBinary($fileWriter, $finalChunk);
            sodium_memzero($state);

            return $bytesWritten;
        } finally {
            $fileReader->releaseLock();
        }
    }

    private function forEachChunk(SafeFileReader $fileReader, int $chunkSize, string $kind, callable $consumer): void
    {
        foreach ($fileReader->binary($chunkSize) as $chunk) {
            $chunk = $this->normalizeChunk($chunk, $kind);
            if ($chunk === null) {
                continue;
            }

            $consumer($chunk);
        }
    }

    private function incrementNonce(string $nonce): string
    {
        $length = strlen($nonce);
        if ($length === 0) {
            throw new RuntimeException('Nonce must not be empty.');
        }

        $bytes = str_split($nonce);

        for ($index = $length - 1; $index >= 0; $index--) {
            $next = (ord($bytes[$index]) + 1) & 0xFF;
            $bytes[$index] = chr($next);

            if ($next !== 0) {
                break;
            }
        }

        return implode('', $bytes);
    }

    private function normalizeChunk(mixed $chunk, string $kind): ?string
    {
        if ($chunk === null || $chunk === '') {
            return null;
        }

        if (!is_string($chunk)) {
            throw new RuntimeException(sprintf('Invalid %s chunk encountered.', $kind));
        }

        return $chunk;
    }

    private function replaceOutput(string $temporaryPath, string $outputPath): void
    {
        if (!file_exists($outputPath)) {
            if (!rename($temporaryPath, $outputPath)) {
                throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
            }

            return;
        }

        if (!is_file($outputPath)) {
            throw new FileAccessException('Output path is not a file: ' . $outputPath);
        }

        if (PHP_OS_FAMILY !== 'Windows' && rename($temporaryPath, $outputPath)) {
            return;
        }

        $backupPath = $temporaryPath . '.backup';
        if (!rename($outputPath, $backupPath)) {
            throw new FileAccessException('Unable to back up the existing output file: ' . $outputPath);
        }

        if (rename($temporaryPath, $outputPath)) {
            if (!unlink($backupPath) && is_file($backupPath)) {
                throw new FileAccessException('Unable to delete the previous output file backup.');
            }

            return;
        }

        if (!rename($backupPath, $outputPath)) {
            throw new FileAccessException('Unable to restore the existing output file after replacement failed.');
        }

        throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
    }

    private function writeBinary(SafeFileWriter $fileWriter, string $data): int
    {
        $written = $fileWriter->__call('binary', [$data]);
        if ($written === false) {
            throw new RuntimeException('Failed to write output chunk.');
        }

        return strlen($data);
    }

    /**
     * @template TResult
     * @param \Closure(SafeFileWriter): TResult $operation
     * @return TResult
     */
    private function writeSafely(string $outputPath, \Closure $operation): mixed
    {
        $directory = dirname($outputPath);
        if (!is_dir($directory) || !is_writable($directory)) {
            throw new FileAccessException('Output directory is not writable: ' . $directory);
        }

        $temporaryPath = tempnam($directory, '.epicrypt-');
        if ($temporaryPath === false) {
            throw new FileAccessException('Unable to create a temporary output file.');
        }

        $fileWriter = new SafeFileWriter($temporaryPath, false);
        $committed = false;

        try {
            $result = $operation($fileWriter);
            $fileWriter->close();

            $this->replaceOutput($temporaryPath, $outputPath);

            $committed = true;

            return $result;
        } finally {
            if (!$committed) {
                try {
                    $fileWriter->close();
                } finally {
                    if (is_file($temporaryPath) && !unlink($temporaryPath) && is_file($temporaryPath)) {
                        throw new FileAccessException('Unable to delete temporary output file.');
                    }
                }
            }
        }
    }
}
