<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\WrappedSecretVersion;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\VersionedPayload;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyStatus;

final class WrappedSecretManager
{
    private const string ALGORITHM_ID = 'secretbox';

    public function rewrap(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        string $oldMasterSecret,
        #[\SensitiveParameter]
        string $newMasterSecret,
    ): string {
        return $this->wrap($this->unwrap($wrappedSecret, $oldMasterSecret), $newMasterSecret);
    }

    /** @param iterable<string, string>|KeyRing $masterSecrets */
    public function rewrapWithAnyBinaryKey(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
        #[\SensitiveParameter]
        string $newMasterSecret,
    ): string {
        return $this->wrapWithBinaryKey(
            $this->unwrapWithAnyBinaryKeyResult($wrappedSecret, $masterSecrets)->plaintext,
            $newMasterSecret,
        );
    }

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function rewrapWithAnyKey(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
        #[\SensitiveParameter]
        string $newMasterSecret,
    ): string {
        return $this->wrap($this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets)->plaintext, $newMasterSecret);
    }

    public function rewrapWithBinaryKeys(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        string $oldMasterSecret,
        #[\SensitiveParameter]
        string $newMasterSecret,
    ): string {
        return $this->wrapWithBinaryKey(
            $this->unwrapWithBinaryKey($wrappedSecret, $oldMasterSecret),
            $newMasterSecret,
        );
    }

    public function unwrap(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        string $masterSecret,
    ): string {
        return $this->unwrapWithBinaryKey($wrappedSecret, $this->decodeMasterSecret($masterSecret, false));
    }

    /** @param iterable<string, string>|KeyRing $masterSecrets */
    public function unwrapWithAnyBinaryKey(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
    ): string {
        return $this->unwrapWithAnyBinaryKeyResult($wrappedSecret, $masterSecrets)->plaintext;
    }

    /** @param iterable<string, string>|KeyRing $masterSecrets */
    public function unwrapWithAnyBinaryKeyResult(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
    ): UnwrappedSecretResult {
        return $this->unwrapCandidateSet($wrappedSecret, $masterSecrets, true);
    }

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function unwrapWithAnyKey(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
    ): string {
        return $this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets)->plaintext;
    }

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function unwrapWithAnyKeyResult(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
    ): UnwrappedSecretResult {
        return $this->unwrapCandidateSet($wrappedSecret, $masterSecrets, false);
    }

    public function unwrapWithBinaryKey(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        string $masterSecret,
    ): string {
        $payload = $this->parseWrappedPayload($wrappedSecret);
        $key = $this->decodeMasterSecret($masterSecret, true);

        $plaintext = sodium_crypto_secretbox_open(
            Base64Url::decode($payload['ciphertext']),
            Base64Url::decode($payload['nonce']),
            $key,
        );

        if ($plaintext === false) {
            throw new SecretProtectionException('Secret unwrap failed.');
        }

        return $plaintext;
    }

    public function unwrapWithKeyRing(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        KeyRing $masterSecrets,
    ): string {
        return $this->unwrapWithKeyRingResult($wrappedSecret, $masterSecrets)->plaintext;
    }

    public function unwrapWithKeyRingResult(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        KeyRing $masterSecrets,
    ): UnwrappedSecretResult {
        return $this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets);
    }

    public function wrap(
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        string $masterSecret,
        ?string $keyId = null,
    ): string {
        return $this->wrapWithBinaryKey($secret, $this->decodeMasterSecret($masterSecret, false), $keyId);
    }

    public function wrapWithBinaryKey(
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        string $masterSecret,
        ?string $keyId = null,
    ): string {
        $key = $this->decodeMasterSecret($masterSecret, true);

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($secret, $nonce, $key);

        return VersionedPayload::encodeCompact(
            WrappedSecretVersion::V2->value,
            self::ALGORITHM_ID,
            $keyId,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    public function wrapWithBinaryKeyRing(
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        KeyRing $keyRing,
    ): string {
        try {
            $entry = $keyRing->activeForWrite(KeyPurpose::SECRET_WRAPPING, self::ALGORITHM_ID);
        } catch (\Throwable $exception) {
            throw new SecretProtectionException('An active secret-wrapping key is required.', 0, $exception);
        }

        return $this->wrapWithBinaryKey($secret, $entry->key, $entry->id);
    }

    public function wrapWithKeyRing(
        #[\SensitiveParameter]
        string $secret,
        #[\SensitiveParameter]
        KeyRing $keyRing,
    ): string {
        try {
            $entry = $keyRing->activeForWrite(KeyPurpose::SECRET_WRAPPING, self::ALGORITHM_ID);
        } catch (\Throwable $exception) {
            throw new SecretProtectionException('An active secret-wrapping key is required.', 0, $exception);
        }

        return $this->wrap($secret, $entry->key, $entry->id);
    }

    private function decodeMasterSecret(#[\SensitiveParameter] string $masterSecret, bool $isBinary): string
    {
        try {
            return BinaryKey::fixedLength($masterSecret, $isBinary, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'Master secret');
        } catch (\Throwable $e) {
            throw new SecretProtectionException('Master secret must be 32 bytes long.', 0, $e);
        }
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(#[\SensitiveParameter] iterable|KeyRing $keys): array
    {
        try {
            return KeyCandidates::orderedEntries(
                $keys,
                'All master secret candidates must be non-empty strings.',
                'At least one master secret candidate is required.',
                KeyPurpose::SECRET_WRAPPING,
                self::ALGORITHM_ID,
            );
        } catch (\InvalidArgumentException $e) {
            throw new SecretProtectionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array{nonce: string, ciphertext: string, key_id: ?string}
     */
    private function parseWrappedPayload(#[\SensitiveParameter] string $wrappedSecret): array
    {
        $compactPayload = VersionedPayload::parseCompact($wrappedSecret, WrappedSecretVersion::V2->value);
        if ($compactPayload === null) {
            throw new SecretProtectionException('Invalid wrapped secret format.');
        }

        if ($compactPayload->algorithm !== self::ALGORITHM_ID) {
            throw new SecretProtectionException('Unsupported wrapped secret algorithm.');
        }

        return [
            'nonce' => $compactPayload->nonce,
            'ciphertext' => $compactPayload->ciphertext,
            'key_id' => $compactPayload->keyId,
        ];
    }

    /** @param iterable<string, string>|KeyRing $masterSecrets */
    private function unwrapCandidateSet(
        #[\SensitiveParameter]
        string $wrappedSecret,
        #[\SensitiveParameter]
        iterable|KeyRing $masterSecrets,
        bool $binary,
    ): UnwrappedSecretResult {
        if ($masterSecrets instanceof KeyRing) {
            $payload = $this->parseWrappedPayload($wrappedSecret);
            if ($payload['key_id'] === null) {
                throw new SecretProtectionException('Wrapped secret key id is required for KeyRing decryption.');
            }
            $entry = $masterSecrets->resolveForRead($payload['key_id'], KeyPurpose::SECRET_WRAPPING, self::ALGORITHM_ID);
            if ($entry === null) {
                throw new SecretProtectionException(sprintf('Master secret key id "%s" was not found in the key ring.', $payload['key_id']));
            }

            try {
                return new UnwrappedSecretResult(
                    $binary
                        ? $this->unwrapWithBinaryKey($wrappedSecret, $entry->key)
                        : $this->unwrap($wrappedSecret, $entry->key),
                    $payload['key_id'],
                    $entry->status === KeyStatus::FALLBACK,
                );
            } catch (SecretProtectionException $e) {
                throw new SecretProtectionException(
                    sprintf('Secret unwrap failed for key id "%s".', $payload['key_id']),
                    0,
                    $e,
                );
            }
        }

        $lastException = null;
        foreach ($this->orderedKeyEntries($masterSecrets) as $entry) {
            try {
                return new UnwrappedSecretResult(
                    $binary
                        ? $this->unwrapWithBinaryKey($wrappedSecret, $entry['key'])
                        : $this->unwrap($wrappedSecret, $entry['key']),
                    $entry['id'],
                    !$entry['active'],
                );
            } catch (SecretProtectionException $e) {
                $lastException = $e;
            }
        }

        throw new SecretProtectionException('Secret unwrap failed for every supplied master secret.', 0, $lastException);
    }
}
