<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Enum\StreamAlgorithm;
use Infocyph\Epicrypt\Crypto\SecretStream;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\FileAccessException;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Throwable;

final readonly class FileProtector
{
    public function __construct(
        private StreamAlgorithm $algorithm = StreamAlgorithm::XCHACHA20POLY1305,
        private bool $allowUnauthenticatedStream = false,
        private ?\Closure $renameOperation = null,
    ) {}

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN): self
    {
        return new self($profile->defaultStreamAlgorithm());
    }

    public function decrypt(
        string $inputPath,
        string $outputPath,
        string $key,
        int $chunkSize = 8192,
        bool $keyIsBinary = false,
    ): void {
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), $this->algorithm, '', $this->allowUnauthenticatedStream);
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
        $this->assertReadableFile($inputPath);
        $stream = new SecretStream($this->decodeKey($key, $keyIsBinary), $this->algorithm, '', $this->allowUnauthenticatedStream);

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
        $outputPath = $this->temporaryPathFor($path . '.rotated');
        $result = $this->reencryptWithAnyKey($path, $outputPath, $keys, $newKey, $chunkSize, $keysAreBinary, $newKeyIsBinary);
        $backupPath = $this->temporaryPathFor($path . '.backup');
        $backupCreated = false;

        try {
            $backupCreated = $this->createBackupIfPresent($path, $backupPath);
            $this->finalizeRotation($outputPath, $path);
        } catch (Throwable $e) {
            $this->rollbackRotation($path, $outputPath, $backupPath, $backupCreated, $e);
        } finally {
            $this->cleanupBackupAfterSuccess($backupPath, $backupCreated, $path);
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

    private function assertReadableFile(string $path): void
    {
        if (!file_exists($path) || !is_readable($path)) {
            throw new FileAccessException('Input file is not readable: ' . $path);
        }
    }

    private function cleanupBackupAfterSuccess(string $backupPath, bool $backupCreated, string $path): void
    {
        if ($backupCreated && file_exists($backupPath) && is_file($path)) {
            $this->deleteIfExists($backupPath);
        }
    }

    private function createBackupIfPresent(string $path, string $backupPath): bool
    {
        if (!file_exists($path)) {
            return false;
        }

        if (!$this->renamePath($path, $backupPath)) {
            throw new FileAccessException('Unable to create backup during in-place rotation: ' . $path);
        }

        return true;
    }

    private function decodeKey(string $key, bool $keyIsBinary): string
    {
        try {
            return BinaryKey::aeadKey($key, $keyIsBinary, $this->algorithm->keyLength(), 'Stream key');
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException(sprintf('Stream key must be %d bytes.', $this->algorithm->keyLength()), 0, $e);
        }
    }

    private function deleteIfExists(string $path): void
    {
        if (file_exists($path) && !unlink($path) && file_exists($path)) {
            throw new FileAccessException('Unable to delete temporary file: ' . $path);
        }
    }

    private function finalizeRotation(string $outputPath, string $path): void
    {
        if (!$this->renamePath($outputPath, $path)) {
            throw new FileAccessException('Unable to finalize in-place rotation for file: ' . $path);
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

    private function removePathForRollback(string $path): bool
    {
        if (is_file($path)) {
            return unlink($path);
        }

        if (is_dir($path)) {
            return rmdir($path);
        }

        return !file_exists($path);
    }

    private function renamePath(string $from, string $to): bool
    {
        if ($this->renameOperation instanceof \Closure) {
            return (bool) ($this->renameOperation)($from, $to);
        }

        return rename($from, $to);
    }

    private function rollbackRotation(string $path, string $outputPath, string $backupPath, bool $backupCreated, Throwable $cause): never
    {
        $this->deleteIfExists($outputPath);

        if ($backupCreated && file_exists($backupPath)) {
            if (file_exists($path) && !$this->removePathForRollback($path)) {
                throw new FileAccessException('Rollback failed while preparing path restoration: ' . $path, 0, $cause);
            }

            if (!file_exists($path) && !$this->renamePath($backupPath, $path)) {
                throw new FileAccessException('Rollback failed while restoring backup: ' . $path, 0, $cause);
            }
        }

        throw new FileAccessException('Unable to complete in-place file rotation.', 0, $cause);
    }

    private function temporaryPathFor(string $targetPath): string
    {
        $directory = dirname($targetPath);
        $base = basename($targetPath);

        return $directory . DIRECTORY_SEPARATOR . '.' . $base . '.epicrypt.' . bin2hex(random_bytes(6)) . '.tmp';
    }
}
