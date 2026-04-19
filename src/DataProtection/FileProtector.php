<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Throwable;

final readonly class FileProtector
{
    public function __construct(
        private StreamAlgorithm $algorithm = StreamAlgorithm::XCHACHA20POLY1305,
        private SecurityProfile $profile = SecurityProfile::MODERN,
    ) {}

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN): self
    {
        return new self($profile->defaultStreamAlgorithm(), $profile);
    }

    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), $this->algorithm, '');
        $stream->decrypt($inputPath, $outputPath, $chunkSize);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function decryptWithAnyKey(
        string $inputPath,
        string $outputPath,
        iterable|KeyRing $keys,
        int $chunkSize = 8192,
        bool $keysAreBinary = false,
    ): FileMigrationResult {
        $lastException = null;

        foreach ($this->orderedKeyEntries($keys) as $entry) {
            try {
                $this->decrypt($inputPath, $outputPath, $entry['key'], $chunkSize, $keysAreBinary);

                return new FileMigrationResult($outputPath, $entry['id'], !$entry['active']);
            } catch (Throwable $e) {
                $lastException = $e;
            }
        }

        throw new FileAccessException('Unable to decrypt file with any supplied key.', 0, $lastException);
    }

    public function encrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): int {
        $this->assertCanWrite('File encryption is disabled for the legacy-decrypt-only profile.');
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), $this->algorithm, '');

        return $stream->encrypt($inputPath, $outputPath, $chunkSize);
    }

    public function reencrypt(
        string $inputPath,
        string $outputPath,
        string $oldKey,
        string $newKey,
        int $chunkSize = 8192,
        bool $oldKeyIsBinary = false,
        bool $newKeyIsBinary = false,
    ): FileMigrationResult {
        $tempPath = $this->temporaryPathFor($outputPath);

        try {
            $this->decrypt($inputPath, $tempPath, $oldKey, $chunkSize, $oldKeyIsBinary);
            $this->encrypt($tempPath, $outputPath, $newKey, $chunkSize, $newKeyIsBinary);

            return new FileMigrationResult($outputPath);
        } finally {
            $this->deleteIfExists($tempPath);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function reencryptInPlaceWithAnyKey(
        string $path,
        iterable|KeyRing $keys,
        string $newKey,
        int $chunkSize = 8192,
        bool $keysAreBinary = false,
        bool $newKeyIsBinary = false,
    ): FileMigrationResult {
        $outputPath = $this->temporaryPathFor($path . '.migrated');
        $result = $this->reencryptWithAnyKey($path, $outputPath, $keys, $newKey, $chunkSize, $keysAreBinary, $newKeyIsBinary);

        if (file_exists($path) && !unlink($path)) {
            $this->deleteIfExists($outputPath);

            throw new FileAccessException('Unable to replace original file during in-place migration: ' . $path);
        }

        if (!rename($outputPath, $path)) {
            $this->deleteIfExists($outputPath);

            throw new FileAccessException('Unable to finalize in-place migration for file: ' . $path);
        }

        return new FileMigrationResult($path, $result->matchedKeyId, $result->usedFallbackKey);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     */
    public function reencryptWithAnyKey(
        string $inputPath,
        string $outputPath,
        iterable|KeyRing $keys,
        string $newKey,
        int $chunkSize = 8192,
        bool $keysAreBinary = false,
        bool $newKeyIsBinary = false,
    ): FileMigrationResult {
        $tempPath = $this->temporaryPathFor($outputPath);
        $result = $this->decryptWithAnyKey($inputPath, $tempPath, $keys, $chunkSize, $keysAreBinary);

        try {
            $this->encrypt($tempPath, $outputPath, $newKey, $chunkSize, $newKeyIsBinary);

            return new FileMigrationResult($outputPath, $result->matchedKeyId, $result->usedFallbackKey);
        } finally {
            $this->deleteIfExists($tempPath);
        }
    }

    private function assertCanWrite(string $message): void
    {
        if (!$this->profile->allowsWrites()) {
            throw new FileAccessException($message);
        }
    }

    private function assertReadableFile(string $path): void
    {
        if (!file_exists($path) || !is_readable($path)) {
            throw new FileAccessException('Input file is not readable: ' . $path);
        }
    }

    private function decodeKey(string $key, bool $keyIsBinary): string
    {
        $decodedKey = $keyIsBinary ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES) {
            throw new InvalidKeyException('Stream key must be 32 bytes.');
        }

        return $decodedKey;
    }

    private function deleteIfExists(string $path): void
    {
        if (file_exists($path) && !unlink($path) && file_exists($path)) {
            throw new FileAccessException('Unable to delete temporary file: ' . $path);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::orderedEntries(
                $keys,
                'All file key candidates must be non-empty strings.',
                'At least one file key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new FileAccessException($e->getMessage(), 0, $e);
        }
    }

    private function temporaryPathFor(string $targetPath): string
    {
        $directory = dirname($targetPath);
        $base = basename($targetPath);

        return $directory . DIRECTORY_SEPARATOR . '.' . $base . '.epicrypt.' . bin2hex(random_bytes(6)) . '.tmp';
    }
}
