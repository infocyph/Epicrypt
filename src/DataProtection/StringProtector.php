<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Crypto\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\DataProtection\Support\ProtectionContext;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Throwable;

final readonly class StringProtector implements EncryptorInterface, DecryptorInterface
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
        private SecurityProfile $profile = SecurityProfile::MODERN,
    ) {}

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN): self
    {
        return new self(profile: $profile);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function decrypt(string $ciphertext, mixed $key, array $context = []): string
    {
        return $this->cipher->decrypt($ciphertext, $key, ProtectionContext::normalize($context));
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
        $normalized = ProtectionContext::normalize($context);
        $lastException = null;

        foreach ($this->orderedKeyEntries($keys) as $entry) {
            try {
                return new StringUnprotectResult(
                    $this->decrypt($ciphertext, $entry['key'], $normalized),
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
     * @param array<string, mixed> $context
     */
    public function encrypt(string $plaintext, mixed $key, array $context = []): string
    {
        $this->assertCanWrite('String protection writes are disabled for the legacy-decrypt-only profile.');

        return $this->cipher->encrypt($plaintext, $key, ProtectionContext::normalize($context));
    }

    /**
     * @param array<string, mixed> $currentContext
     * @param array<string, mixed> $legacyContext
     */
    public function reencrypt(string $ciphertext, mixed $oldKey, mixed $newKey, array $legacyContext = [], array $currentContext = []): string
    {
        $plaintext = $this->decrypt($ciphertext, $oldKey, $legacyContext);

        return $this->encrypt($plaintext, $newKey, $currentContext);
    }

    /**
     * @param array<string, mixed> $currentContext
     * @param array<string, mixed> $legacyContext
     * @param iterable<string, string>|KeyRing $legacyKeys
     */
    public function reencryptWithAnyKey(string $ciphertext, iterable|KeyRing $legacyKeys, mixed $newKey, array $legacyContext = [], array $currentContext = []): string
    {
        $plaintext = $this->decryptWithAnyKeyResult($ciphertext, $legacyKeys, $legacyContext)->plaintext;

        return $this->encrypt($plaintext, $newKey, $currentContext);
    }

    private function assertCanWrite(string $message): void
    {
        if (!$this->profile->allowsWrites()) {
            throw new EncryptionException($message);
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
                'All key candidates must be non-empty strings.',
                'At least one key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }
}
