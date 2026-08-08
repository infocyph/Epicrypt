<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Pathwise\FileManager\SafeFileReader;
use Infocyph\Pathwise\FileManager\SafeFileWriter;
use RuntimeException;
use Throwable;

final readonly class SecretStream
{
    public const int DEFAULT_CHUNK_SIZE = 64 * 1024;

    private const int MAX_CHUNK_SIZE = 16 * 1024 * 1024;

    public function __construct(
        #[\SensitiveParameter]
        private string $key,
        private string $additionalData = '',
        private string $framingPrefix = '',
    ) {
        if (strlen($this->key) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new InvalidKeyException(sprintf(
                'Stream key must be %d bytes.',
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES,
            ));
        }
    }

    public function decrypt(
        string $inputPath,
        string $outputPath,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
    ): void {
        $this->assertPaths($inputPath, $outputPath);
        $this->assertValidChunkSize($chunkSize);

        try {
            $this->writeSafely(
                $outputPath,
                fn(SafeFileWriter $writer) => $this->decryptFrames($inputPath, $writer, $chunkSize),
            );
        } catch (DecryptionException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new DecryptionException('SecretStream decryption failed.', 0, $exception);
        }
    }

    public function encrypt(
        string $inputPath,
        string $outputPath,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
    ): int {
        $this->assertPaths($inputPath, $outputPath);
        $this->assertValidChunkSize($chunkSize);

        try {
            return $this->writeSafely(
                $outputPath,
                fn(SafeFileWriter $writer): int => $this->encryptFrames($inputPath, $writer, $chunkSize),
            );
        } catch (EncryptionException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new EncryptionException('SecretStream encryption failed.', 0, $exception);
        }
    }

    private function assertPaths(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new FileAccessException('Input file is not readable: ' . $inputPath);
        }

        $inputRealPath = realpath($inputPath);
        $outputRealPath = realpath($outputPath);
        if ($inputRealPath !== false && $outputRealPath !== false && $inputRealPath === $outputRealPath) {
            throw new FileAccessException('Input and output must identify different files.');
        }

        if ($outputRealPath === false) {
            $outputDirectory = realpath(dirname($outputPath));
            if ($inputRealPath !== false && $outputDirectory !== false) {
                $candidate = $outputDirectory . DIRECTORY_SEPARATOR . basename($outputPath);
                if ($candidate === $inputRealPath) {
                    throw new FileAccessException('Input and output must identify different files.');
                }
            }
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

    private function consumeFullFrames(
        string &$buffer,
        string &$state,
        SafeFileWriter $writer,
        bool $finalSeen,
        int $frameSize,
    ): bool {
        while (strlen($buffer) >= $frameSize) {
            $ciphertext = substr($buffer, 0, $frameSize);
            $buffer = substr($buffer, $frameSize);
            $finalSeen = $this->decryptFrame($state, $ciphertext, $writer, $finalSeen);
        }

        return $finalSeen;
    }

    private function consumeHeader(string &$buffer): ?string
    {
        if (strlen($buffer) < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            return null;
        }

        $header = substr($buffer, 0, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        $buffer = substr($buffer, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);

        return sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
    }

    private function consumePrefix(string &$buffer): bool
    {
        $prefixLength = strlen($this->framingPrefix);
        if (strlen($buffer) < $prefixLength) {
            return false;
        }

        $actualPrefix = substr($buffer, 0, $prefixLength);
        if (!hash_equals($this->framingPrefix, $actualPrefix)) {
            throw new RuntimeException('Invalid SecretStream framing prefix.');
        }

        $buffer = substr($buffer, $prefixLength);

        return true;
    }

    private function decryptFrame(
        string &$state,
        string $frame,
        SafeFileWriter $writer,
        bool $finalSeen,
    ): bool {
        if ($finalSeen) {
            throw new RuntimeException('Trailing data or a duplicate final frame was found.');
        }

        if (strlen($frame) < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES) {
            throw new RuntimeException('Truncated SecretStream frame.');
        }

        $decrypted = sodium_crypto_secretstream_xchacha20poly1305_pull(
            $state,
            $frame,
            $this->additionalData,
        );
        if ($decrypted === false) {
            throw new RuntimeException('Malformed or corrupted SecretStream frame.');
        }

        [$plaintext, $tag] = $decrypted;
        if (!is_string($plaintext) || !is_int($tag)) {
            throw new RuntimeException('Invalid SecretStream decrypted frame values.');
        }
        $this->writeAll($writer, $plaintext);

        return $tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }

    private function decryptFrames(string $inputPath, SafeFileWriter $writer, int $chunkSize): void
    {
        $reader = new SafeFileReader($inputPath);
        $state = null;

        try {
            $frameSize = $chunkSize + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
            $finalSeen = false;
            $buffer = '';
            $prefixValidated = $this->framingPrefix === '';

            foreach ($reader->chunks($frameSize) as $frame) {
                if ($frame === '') {
                    continue;
                }
                $buffer .= $frame;

                if (!$prefixValidated) {
                    $prefixValidated = $this->consumePrefix($buffer);
                }

                if ($prefixValidated && $state === null) {
                    $state = $this->consumeHeader($buffer);
                }

                if ($state !== null) {
                    $finalSeen = $this->consumeFullFrames($buffer, $state, $writer, $finalSeen, $frameSize);
                }
            }

            if (!$prefixValidated || $state === null) {
                throw new RuntimeException('Invalid or truncated SecretStream header.');
            }

            if ($buffer !== '') {
                $finalSeen = $this->decryptFrame($state, $buffer, $writer, $finalSeen);
            }

            if (!$finalSeen) {
                throw new RuntimeException('SecretStream final frame is missing.');
            }
        } finally {
            if (is_string($state)) {
                sodium_memzero($state);
            }
            $reader->releaseLock();
        }
    }

    private function encryptFrames(string $inputPath, SafeFileWriter $writer, int $chunkSize): int
    {
        [$state, $header] = $this->initializePush();
        $reader = new SafeFileReader($inputPath);
        $written = $this->writeAll($writer, $this->framingPrefix . $header);

        try {
            $buffer = null;
            foreach ($reader->chunks($chunkSize) as $chunk) {
                if ($chunk === '') {
                    continue;
                }

                if ($buffer !== null) {
                    $frame = sodium_crypto_secretstream_xchacha20poly1305_push(
                        $state,
                        $buffer,
                        $this->additionalData,
                        SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                    );
                    $written += $this->writeAll($writer, $frame);
                }
                $buffer = $chunk;
            }

            $finalFrame = sodium_crypto_secretstream_xchacha20poly1305_push(
                $state,
                $buffer ?? '',
                $this->additionalData,
                SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
            );

            return $written + $this->writeAll($writer, $finalFrame);
        } finally {
            sodium_memzero($state);
            $reader->releaseLock();
        }
    }

    /** @return array{string, string} */
    private function initializePush(): array
    {
        $initialized = sodium_crypto_secretstream_xchacha20poly1305_init_push($this->key);
        $state = $initialized[0] ?? null;
        $header = $initialized[1] ?? null;
        if (!is_string($state) || !is_string($header)) {
            throw new RuntimeException('Unable to initialize SecretStream encryption state.');
        }

        return [$state, $header];
    }

    private function replaceOutput(string $temporaryPath, string $outputPath): void
    {
        if (!file_exists($outputPath) || PHP_OS_FAMILY !== 'Windows') {
            if (!rename($temporaryPath, $outputPath)) {
                throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
            }

            return;
        }

        if (!is_file($outputPath)) {
            throw new FileAccessException('Output path is not a file: ' . $outputPath);
        }

        $backupPath = $temporaryPath . '.backup';
        if (!rename($outputPath, $backupPath)) {
            throw new FileAccessException('Unable to preserve the existing output file.');
        }

        if (rename($temporaryPath, $outputPath)) {
            if (!unlink($backupPath) && is_file($backupPath)) {
                throw new FileAccessException('Unable to remove the replaced output backup.');
            }

            return;
        }

        if (!rename($backupPath, $outputPath)) {
            throw new FileAccessException('Unable to restore the existing output file.');
        }

        throw new FileAccessException('Unable to finalize output file: ' . $outputPath);
    }

    private function writeAll(SafeFileWriter $writer, string $data): int
    {
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = $writer->writeBinary(substr($data, $offset));
            if ($written < 1) {
                throw new RuntimeException('Unable to write the complete output frame.');
            }
            $offset += $written;
        }

        return $length;
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

        $writer = new SafeFileWriter($temporaryPath);
        $committed = false;

        try {
            $result = $operation($writer);
            $writer->close();
            $this->replaceOutput($temporaryPath, $outputPath);
            $committed = true;

            return $result;
        } finally {
            if (!$committed && is_file($temporaryPath)) {
                $writer->close();
                if (!unlink($temporaryPath) && is_file($temporaryPath)) {
                    throw new FileAccessException('Unable to remove temporary output file.');
                }
            }
        }
    }
}
