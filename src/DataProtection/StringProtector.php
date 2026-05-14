<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Crypto\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\DataProtection\Support\ProtectionContext;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\Enum\EncryptedPayloadVersion;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\VersionedPayload;
use Infocyph\Epicrypt\Security\KeyRing;
use Throwable;

final readonly class StringProtector implements DecryptorInterface, EncryptorInterface
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
    ) {}

    public static function forProfile(): self
    {
        return new self();
    }

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        return $this->cipher->decrypt($ciphertext, $key, ProtectionContext::fromArray($context)->toArray());
    }

    /**
     * @param array<string, mixed> $context
     * @param iterable<string, string>|KeyRing $keys
     */
    public function decryptWithAnyKey(string $ciphertext, iterable|KeyRing $keys, array $context = []): string
    {
        return $this->decryptWithAnyKeyResult($ciphertext, $keys, $context)->plaintext;
    }

    /**
     * @param array<string, mixed> $context
     * @param iterable<string, string>|KeyRing $keys
     */
    public function decryptWithAnyKeyResult(string $ciphertext, iterable|KeyRing $keys, array $context = []): StringUnprotectResult
    {
        if ($keys instanceof KeyRing) {
            return $this->decryptWithKeyRingResult($ciphertext, $keys, $context);
        }

        $normalized = ProtectionContext::fromArray($context)->toArray();

        return $this->decryptWithOrderedEntries($ciphertext, $normalized, $this->orderedKeyEntries($keys));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function decryptWithKeyRing(string $ciphertext, KeyRing $keyRing, array $context = []): string
    {
        return $this->decryptWithKeyRingResult($ciphertext, $keyRing, $context)->plaintext;
    }

    /**
     * @param array<string, mixed> $context
     */
    public function decryptWithKeyRingResult(string $ciphertext, KeyRing $keyRing, array $context = []): StringUnprotectResult
    {
        $normalized = ProtectionContext::fromArray($context)->toArray();
        $compactPayload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V1->value);

        if ($compactPayload !== null && $compactPayload->algorithm === SecretBoxCipher::ALGORITHM_ID && $compactPayload->keyId !== null) {
            $key = $keyRing->keys()[$compactPayload->keyId] ?? null;
            if ($key === null) {
                throw new DecryptionException(sprintf('Protected payload key id "%s" was not found in the key ring.', $compactPayload->keyId));
            }

            try {
                return new StringUnprotectResult(
                    $this->decrypt($ciphertext, $key, $normalized),
                    $compactPayload->keyId,
                    false,
                );
            } catch (Throwable $e) {
                throw new DecryptionException(sprintf('Unable to decrypt protected string with key id "%s".', $compactPayload->keyId), 0, $e);
            }
        }

        return $this->decryptWithOrderedEntries($ciphertext, $normalized, $this->orderedKeyEntries($keyRing));
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        return $this->cipher->encrypt($plaintext, $key, ProtectionContext::fromArray($context)->toArray());
    }

    /**
     * @param array<string, mixed> $context
     */
    public function encryptWithKeyRing(string $plaintext, KeyRing $keyRing, array $context = []): string
    {
        $activeKey = $keyRing->activeKey();
        $activeKeyId = $keyRing->activeKeyId();
        if ($activeKey === null || $activeKeyId === null) {
            throw new ConfigurationException('Key ring active key id is required for protected-string encryption.');
        }

        $normalized = ProtectionContext::fromArray($context);

        return $this->encrypt(
            $plaintext,
            $activeKey,
            array_merge($normalized->toArray(), ['key_id' => $activeKeyId]),
        );
    }

    public function inspect(string $ciphertext): StringProtectInspectResult
    {
        $payload = VersionedPayload::parseCompact($ciphertext, EncryptedPayloadVersion::V1->value);
        if ($payload === null) {
            throw new DecryptionException('Invalid protected string format.');
        }

        return new StringProtectInspectResult(EncryptedPayloadVersion::V1->value, $payload->algorithm, $payload->keyId);
    }

    public function needsReencrypt(string $ciphertext, ?string $activeKeyId = null): bool
    {
        $info = $this->inspect($ciphertext);

        if ($info->algorithm !== SecretBoxCipher::ALGORITHM_ID) {
            return true;
        }

        return $this->needsRotation($ciphertext, $activeKeyId);
    }

    public function needsRotation(string $ciphertext, ?string $activeKeyId): bool
    {
        if ($activeKeyId === null || $activeKeyId === '') {
            return false;
        }

        $info = $this->inspect($ciphertext);

        return $info->keyId === null || !hash_equals($activeKeyId, $info->keyId);
    }

    /**
     * @param array<string, mixed> $currentContext
     * @param array<string, mixed> $sourceContext
     */
    public function reencrypt(string $ciphertext, mixed $oldKey, mixed $newKey, array $sourceContext = [], array $currentContext = []): string
    {
        $plaintext = $this->decrypt($ciphertext, $oldKey, $sourceContext);

        return $this->encrypt($plaintext, $newKey, $currentContext);
    }

    /**
     * @param array<string, mixed> $currentContext
     * @param array<string, mixed> $sourceContext
     * @param iterable<string, string>|KeyRing $sourceKeys
     */
    public function reencryptWithAnyKey(string $ciphertext, iterable|KeyRing $sourceKeys, mixed $newKey, array $sourceContext = [], array $currentContext = []): string
    {
        $plaintext = $this->decryptWithAnyKeyResult($ciphertext, $sourceKeys, $sourceContext)->plaintext;

        return $this->encrypt($plaintext, $newKey, $currentContext);
    }

    /**
     * @param array<string, mixed> $context
     * @param list<array{id: ?string, key: string, active: bool}> $entries
     */
    private function decryptWithOrderedEntries(string $ciphertext, array $context, array $entries): StringUnprotectResult
    {
        $lastException = null;

        foreach ($entries as $entry) {
            try {
                return new StringUnprotectResult(
                    $this->decrypt($ciphertext, $entry['key'], $context),
                    $entry['id'],
                    !$entry['active'],
                );
            } catch (Throwable $e) {
                $lastException = $e;
            }
        }

        throw new DecryptionException('Unable to decrypt protected string with any supplied key.', 0, $lastException);
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
                'All key candidates must be non-empty strings.',
                'At least one key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }
}
