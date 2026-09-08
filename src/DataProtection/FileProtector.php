<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Internal\StreamIO;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;
use Psr\Clock\ClockInterface;

final readonly class FileProtector
{
    private const string ALGORITHM = 'xchacha20-poly1305-secretstream';

    private const string DOMAIN = 'file';

    private const int MAX_PREFIX_SIZE = 32 * 1024;

    public function __construct(private ClockInterface $clock = new SystemClock()) {}

    public function protect(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        return $this->protectWithBinaryKey(
            $inputPath,
            $outputPath,
            Base64Url::decode($key),
            $options,
            $chunkSize,
        );
    }

    /**
     * Protect from the current input position into the current output position.
     * The caller owns stream lifetime and publication/rollback semantics.
     *
     * @param resource $input
     * @param resource $output
     */
    public function protectStream(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        return $this->protectStreamWithBinaryKey(
            $input,
            $output,
            Base64Url::decode($key),
            $options,
            $chunkSize,
        );
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    public function protectStreamWithBinaryKey(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);

        $createdAt = $this->clock->now()->getTimestamp();
        $prefix = $this->encodePrefix($options, $createdAt);
        StreamIO::writeAll($output, $prefix . "\n");
        new SecretStream($key, $prefix)->encryptStream($input, $output, $chunkSize);

        return new ProtectionMetadata(
            self::DOMAIN,
            $options->purpose,
            $createdAt,
            $options->keyId,
        );
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    public function protectStreamWithKeyRing(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);
        $entry = $keyRing->activeForWrite(KeyPurpose::FILE_PROTECTION, self::ALGORITHM);

        return $this->protectStream(
            $input,
            $output,
            $entry->key,
            new ProtectionOptions(
                $options->purpose,
                $options->additionalAuthenticatedData,
                $entry->id,
            ),
            $chunkSize,
        );
    }

    public function protectWithBinaryKey(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $metadata = StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input): ProtectionMetadata => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output): ProtectionMetadata => $this->protectStreamWithBinaryKey(
                    $input,
                    $output,
                    $key,
                    $options,
                    $chunkSize,
                ),
            ),
        );

        return $this->pathResult($outputPath, $metadata);
    }

    public function protectWithKeyRing(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $metadata = StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input): ProtectionMetadata => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output): ProtectionMetadata => $this->protectStreamWithKeyRing(
                    $input,
                    $output,
                    $keyRing,
                    $options,
                    $chunkSize,
                ),
            ),
        );

        return $this->pathResult($outputPath, $metadata);
    }

    public function unprotect(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        return $this->unprotectWithBinaryKey(
            $inputPath,
            $outputPath,
            Base64Url::decode($key),
            $options,
            $chunkSize,
        );
    }

    /**
     * Unprotect from the current input position into the current output position.
     * For non-seekable outputs, callers should stage output until this method succeeds.
     *
     * @param resource $input
     * @param resource $output
     */
    public function unprotectStream(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        return $this->unprotectStreamWithBinaryKey(
            $input,
            $output,
            Base64Url::decode($key),
            $options,
            $chunkSize,
        );
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    public function unprotectStreamWithBinaryKey(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);

        [$prefix, $metadata] = $this->readAndValidatePrefixFromStream($input, $options);
        new SecretStream($key, $prefix)->decryptStream($input, $output, $chunkSize);

        return new ProtectionMetadata(
            self::DOMAIN,
            $metadata['purpose'],
            $metadata['created_at'],
            $metadata['kid'],
        );
    }

    /**
     * @param resource $input
     * @param resource $output
     */
    public function unprotectStreamWithKeyRing(
        mixed $input,
        mixed $output,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionMetadata {
        $input = StreamIO::readable($input);
        $output = StreamIO::writable($output);

        [$prefix, $metadata] = $this->readAndValidatePrefixFromStream($input, $options);
        if ($metadata['kid'] === null) {
            throw new DecryptionException('Protected-file key id is required for KeyRing decryption.');
        }

        $entry = $keyRing->resolveForRead($metadata['kid'], KeyPurpose::FILE_PROTECTION, self::ALGORITHM);
        if ($entry === null) {
            throw new DecryptionException('Protected-file key id is not eligible for decryption.');
        }

        new SecretStream(Base64Url::decode($entry->key), $prefix)->decryptStream($input, $output, $chunkSize);

        return new ProtectionMetadata(
            self::DOMAIN,
            $metadata['purpose'],
            $metadata['created_at'],
            $entry->id,
            $entry->status === KeyStatus::FALLBACK,
        );
    }

    public function unprotectWithBinaryKey(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $metadata = StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input): ProtectionMetadata => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output): ProtectionMetadata => $this->unprotectStreamWithBinaryKey(
                    $input,
                    $output,
                    $key,
                    $options,
                    $chunkSize,
                ),
            ),
        );

        return $this->pathResult($outputPath, $metadata);
    }

    public function unprotectWithKeyRing(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        StreamIO::assertDistinctLocalPaths($inputPath, $outputPath);
        $metadata = StreamIO::withReadableLocalFile(
            $inputPath,
            fn($input): ProtectionMetadata => StreamIO::withAtomicLocalOutput(
                $outputPath,
                fn($output): ProtectionMetadata => $this->unprotectStreamWithKeyRing(
                    $input,
                    $output,
                    $keyRing,
                    $options,
                    $chunkSize,
                ),
            ),
        );

        return $this->pathResult($outputPath, $metadata);
    }

    private function encodePrefix(ProtectionOptions $options, int $createdAt): string
    {
        return ProtectedPayload::PREFIX . '.' . Base64Url::encode(Json::encode([
            'v' => 2,
            'domain' => self::DOMAIN,
            'alg' => self::ALGORITHM,
            'kid' => $options->keyId,
            'purpose' => $options->purpose,
            'created_at' => $createdAt,
            'aad' => Base64Url::encode($options->additionalAuthenticatedData),
        ]));
    }

    private function pathResult(string $outputPath, ProtectionMetadata $metadata): ProtectionResult
    {
        return new ProtectionResult(
            $outputPath,
            $metadata->domain,
            $metadata->purpose,
            $metadata->createdAt,
            $metadata->keyId,
            $metadata->usedFallbackKey,
        );
    }

    /**
     * @param resource $input
     * @return array{string, array{v: int, domain: string, alg: string, kid: ?string, purpose: string, created_at: int, aad: string}}
     */
    private function readAndValidatePrefixFromStream(mixed $input, ProtectionOptions $options): array
    {
        try {
            $prefix = StreamIO::readLine($input, self::MAX_PREFIX_SIZE);
        } catch (\Throwable $exception) {
            throw new DecryptionException('Invalid or truncated protected-file header.', 0, $exception);
        }

        if ($prefix === '') {
            throw new DecryptionException('Invalid or truncated protected-file header.');
        }

        $parts = explode('.', $prefix);
        if (count($parts) !== 2 || $parts[0] !== ProtectedPayload::PREFIX) {
            throw new DecryptionException('Invalid protected-file framing.');
        }

        try {
            $metadata = Json::decodeToArray(Base64Url::decode($parts[1]));
        } catch (\Throwable $exception) {
            throw new DecryptionException('Invalid protected-file metadata.', 0, $exception);
        }

        $keys = array_keys($metadata);
        sort($keys);
        if ($keys !== ['aad', 'alg', 'created_at', 'domain', 'kid', 'purpose', 'v']
            || $metadata['v'] !== 2
            || $metadata['domain'] !== self::DOMAIN
            || $metadata['alg'] !== self::ALGORITHM
            || $metadata['purpose'] !== $options->purpose
            || $metadata['aad'] !== Base64Url::encode($options->additionalAuthenticatedData)
            || !is_int($metadata['created_at'])
            || ($metadata['kid'] !== null
                && (!is_string($metadata['kid'])
                    || preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $metadata['kid']) !== 1))
            || ($options->keyId !== null && $metadata['kid'] !== $options->keyId)) {
            throw new DecryptionException('Invalid or mismatched protected-file metadata.');
        }

        return [$prefix, [
            'v' => 2,
            'domain' => self::DOMAIN,
            'alg' => self::ALGORITHM,
            'kid' => $metadata['kid'],
            'purpose' => $options->purpose,
            'created_at' => $metadata['created_at'],
            'aad' => Base64Url::encode($options->additionalAuthenticatedData),
        ]];
    }
}
