<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Pathwise\FileManager\SafeFileReader;
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

    public function protectWithBinaryKey(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        $this->assertLocalPaths($inputPath, $outputPath);
        $createdAt = $this->clock->now()->getTimestamp();
        $prefix = $this->encodePrefix($options, $createdAt);
        new SecretStream($key, $prefix, $prefix . "\n")->encrypt($inputPath, $outputPath, $chunkSize);

        return new ProtectionResult(
            $outputPath,
            self::DOMAIN,
            $options->purpose,
            $createdAt,
            $options->keyId,
        );
    }

    public function protectWithKeyRing(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        $entry = $keyRing->activeForWrite(KeyPurpose::FILE_PROTECTION, self::ALGORITHM);

        return $this->protect(
            $inputPath,
            $outputPath,
            $entry->key,
            new ProtectionOptions(
                $options->purpose,
                $options->additionalAuthenticatedData,
                $entry->id,
            ),
            $chunkSize,
        );
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

    public function unprotectWithBinaryKey(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        string $key,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        $this->assertLocalPaths($inputPath, $outputPath);
        [$prefix, $metadata] = $this->readAndValidatePrefix($inputPath, $options);
        new SecretStream($key, $prefix, $prefix . "\n")->decrypt($inputPath, $outputPath, $chunkSize);

        return new ProtectionResult(
            $outputPath,
            self::DOMAIN,
            $metadata['purpose'],
            $metadata['created_at'],
            $metadata['kid'],
        );
    }

    public function unprotectWithKeyRing(
        string $inputPath,
        string $outputPath,
        #[\SensitiveParameter]
        KeyRing $keyRing,
        ProtectionOptions $options,
        int $chunkSize = SecretStream::DEFAULT_CHUNK_SIZE,
    ): ProtectionResult {
        [, $metadata] = $this->readAndValidatePrefix($inputPath, $options);
        if ($metadata['kid'] === null) {
            throw new DecryptionException('File key id is required for KeyRing decryption.');
        }

        $entry = $keyRing->resolveForRead($metadata['kid'], KeyPurpose::FILE_PROTECTION, self::ALGORITHM);
        if ($entry === null) {
            throw new DecryptionException('File key id is not eligible for decryption.');
        }

        $result = $this->unprotect($inputPath, $outputPath, $entry->key, $options, $chunkSize);

        return new ProtectionResult(
            $result->value,
            $result->domain,
            $result->purpose,
            $result->createdAt,
            $entry->id,
            $entry->status === KeyStatus::FALLBACK,
        );
    }

    private function assertLocalPaths(string $inputPath, string $outputPath): void
    {
        foreach ([$inputPath, $outputPath] as $path) {
            if (preg_match('/\A[A-Za-z][A-Za-z0-9+.-]*:\/\//D', $path) === 1) {
                throw new \Infocyph\Epicrypt\Exception\FileAccessException(
                    'FileProtector supports local filesystem paths only.',
                );
            }
        }
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

    /**
     * @return array{string, array{v: int, domain: string, alg: string, kid: ?string, purpose: string, created_at: int, aad: string}}
     */
    private function readAndValidatePrefix(string $path, ProtectionOptions $options): array
    {
        $reader = new SafeFileReader($path);

        try {
            $chunks = $reader->chunks(self::MAX_PREFIX_SIZE);
            if (!$chunks->valid()) {
                throw new DecryptionException('Invalid or truncated Epicrypt 2.0 file header.');
            }
            $firstChunk = $chunks->current();
        } finally {
            $reader->releaseLock();
        }

        if ($firstChunk === '') {
            throw new DecryptionException('Invalid or truncated Epicrypt 2.0 file header.');
        }

        $newline = strpos($firstChunk, "\n");
        if ($newline === false || $newline === 0) {
            throw new DecryptionException('Invalid or oversized Epicrypt 2.0 file header.');
        }

        $prefix = substr($firstChunk, 0, $newline);
        $parts = explode('.', $prefix);
        if (count($parts) !== 2 || $parts[0] !== ProtectedPayload::PREFIX) {
            throw new DecryptionException('Invalid Epicrypt 2.0 file framing.');
        }

        try {
            $metadata = Json::decodeToArray(Base64Url::decode($parts[1]));
        } catch (\Throwable $exception) {
            throw new DecryptionException('Invalid Epicrypt 2.0 file metadata.', 0, $exception);
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
            throw new DecryptionException('Invalid or mismatched Epicrypt 2.0 file metadata.');
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
