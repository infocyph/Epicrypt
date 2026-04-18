<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\DataProtection;

use Infocyph\Epicrypt\Crypto\Contract\DecryptorInterface;
use Infocyph\Epicrypt\Crypto\Contract\EncryptorInterface;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\DataProtection\Support\ProtectionContext;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Security\KeyRing;
use Throwable;

final readonly class StringProtector implements EncryptorInterface, DecryptorInterface
{
    public function __construct(
        private SecretBoxCipher $cipher = new SecretBoxCipher(),
    ) {}

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
    public function decryptWithAny(string $ciphertext, iterable|KeyRing $keys, array $context = []): string
    {
        $normalized = ProtectionContext::normalize($context);
        $lastException = null;

        foreach ($this->orderedKeys($keys) as $key) {
            try {
                return $this->decrypt($ciphertext, $key, $normalized);
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
    public function reencryptWithAny(string $ciphertext, iterable|KeyRing $legacyKeys, mixed $newKey, array $legacyContext = [], array $currentContext = []): string
    {
        $plaintext = $this->decryptWithAny($ciphertext, $legacyKeys, $legacyContext);

        return $this->encrypt($plaintext, $newKey, $currentContext);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::ordered(
                $keys,
                'All key candidates must be non-empty strings.',
                'At least one key candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new DecryptionException($e->getMessage(), 0, $e);
        }
    }
}
