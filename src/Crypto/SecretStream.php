<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Integration\Runwire\RunwireExecutionContext;
use Infocyph\Epicrypt\Internal\StreamIO;
use Infocyph\Runwire\Exception\CancelledException;
use LogicException;
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
        ?RunwireExecutionContext $context = null,
    ): void {
        $context?->assertActive();
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $this->assertValidChunkSize($chunkSize);

        StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input) => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output) => $this->decryptStream($input, $output, $chunkSize, $context),
                $context === null ? null : static function () use ($context): void {
                    $context->assertActive();
                },
            ),
        );
    }

    /**
     * Decrypt from the current position of $input into the current position of $output.
     * The caller owns stream lifetime and any publication/rollback semantics.
     *
     * @param resource $input
     * @param resource $output
     */
    public function decryptStream(
        mixed $input,
        mixed $output,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
        ?RunwireExecutionContext $context = null,
    ): void {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);
        $this->assertValidChunkSize($chunkSize);

        try {
            $context?->assertActive();
            $this->decryptFrames($input, $output, $chunkSize, $context);
            $context?->assertActive();
        } catch (CancelledException|LogicException|DecryptionException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new DecryptionException('SecretStream decryption failed.', 0, $exception);
        }
    }

    public function encrypt(
        string $inputPath,
        string $outputPath,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
        ?RunwireExecutionContext $context = null,
    ): int {
        $context?->assertActive();
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $this->assertValidChunkSize($chunkSize);

        return StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input): int => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output): int => $this->encryptStream($input, $output, $chunkSize, $context),
                $context === null ? null : static function () use ($context): void {
                    $context->assertActive();
                },
            ),
        );
    }

    /**
     * Encrypt from the current position of $input into the current position of $output.
     * The caller owns stream lifetime and any publication/rollback semantics.
     *
     * @param resource $input
     * @param resource $output
     */
    public function encryptStream(
        mixed $input,
        mixed $output,
        int $chunkSize = self::DEFAULT_CHUNK_SIZE,
        ?RunwireExecutionContext $context = null,
    ): int {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);
        $this->assertValidChunkSize($chunkSize);

        try {
            $context?->assertActive();
            $result = $this->encryptFrames($input, $output, $chunkSize, $context);
            $context?->assertActive();

            return $result;
        } catch (CancelledException|LogicException|EncryptionException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new EncryptionException('SecretStream encryption failed.', 0, $exception);
        }
    }

    /** @param resource $input */
    private function assertNoTrailingData(mixed $input): void
    {
        if (StreamIO::readChunk($input, 1) !== null) {
            throw new RuntimeException('Trailing data or a duplicate final frame was found.');
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

    /** @param resource $output */
    private function decryptFrame(
        #[\SensitiveParameter]
        string &$state,
        string $frame,
        mixed $output,
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
        StreamIO::writeAll($output, $plaintext);

        return $tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    private function decryptFrames(mixed $input, mixed $output, int $chunkSize, ?RunwireExecutionContext $context): void
    {
        $state = $this->initializePullFromStream($input);

        try {
            $this->decryptRemainingFrames($input, $output, $state, $chunkSize, $context);
        } finally {
            sodium_memzero($state);
        }
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    private function decryptRemainingFrames(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        string &$state,
        int $chunkSize,
        ?RunwireExecutionContext $context,
    ): void {
        $frameSize = $chunkSize + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
        $finalSeen = false;

        while (($frame = StreamIO::readChunk($input, $frameSize)) !== null) {
            $context?->checkpoint();
            $shortFrame = strlen($frame) < $frameSize;
            $finalSeen = $this->decryptFrame($state, $frame, $output, $finalSeen);
            $context?->assertActive();

            if ($finalSeen) {
                $this->assertNoTrailingData($input);
                $context?->assertActive();

                return;
            }

            if ($shortFrame) {
                break;
            }
        }

        throw new RuntimeException('SecretStream final frame is missing.');
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    private function encryptFrames(mixed $input, mixed $output, int $chunkSize, ?RunwireExecutionContext $context): int
    {
        [$state, $header] = $this->initializePush();
        $written = 0;

        try {
            $context?->assertActive();
            $written += StreamIO::writeAll($output, $this->framingPrefix . $header);
            $buffer = StreamIO::readChunk($input, $chunkSize);

            if ($buffer === null) {
                $finalFrame = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $state,
                    '',
                    $this->additionalData,
                    SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL,
                );

                $written += StreamIO::writeAll($output, $finalFrame);
                $context?->assertActive();

                return $written;
            }

            while (true) {
                $context?->checkpoint();
                $next = StreamIO::readChunk($input, $chunkSize);
                $final = $next === null;
                $frame = sodium_crypto_secretstream_xchacha20poly1305_push(
                    $state,
                    $buffer,
                    $this->additionalData,
                    $final
                        ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                        : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE,
                );
                $written += StreamIO::writeAll($output, $frame);
                $context?->assertActive();

                if ($final) {
                    return $written;
                }
                $buffer = $next;
            }
        } finally {
            sodium_memzero($state);
        }
    }

    /** @param resource $input */
    private function initializePullFromStream(mixed $input): string
    {
        if ($this->framingPrefix !== '') {
            $prefix = StreamIO::readChunk($input, strlen($this->framingPrefix));
            if ($prefix === null
                || strlen($prefix) !== strlen($this->framingPrefix)
                || !hash_equals($this->framingPrefix, $prefix)) {
                throw new RuntimeException('Invalid or truncated SecretStream framing prefix.');
            }
        }

        $header = StreamIO::readChunk($input, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if ($header === null || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('Invalid or truncated SecretStream header.');
        }

        return sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $this->key);
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
}
