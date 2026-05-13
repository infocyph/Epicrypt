<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;
use Infocyph\Epicrypt\Internal\Enum\WrappedSecretVersion;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\VersionedPayload;
use Infocyph\Epicrypt\Security\KeyRing;

final class WrappedSecretManager
{
    private const string ALGORITHM_ID = 'secretbox';

    public function rewrap(
        string $wrappedSecret,
        string $oldMasterSecret,
        string $newMasterSecret,
        bool $oldMasterSecretIsBinary = false,
        bool $newMasterSecretIsBinary = false,
    ): string {
        $plaintext = $this->unwrap($wrappedSecret, $oldMasterSecret, $oldMasterSecretIsBinary);

        return $this->wrap($plaintext, $newMasterSecret, $newMasterSecretIsBinary);
    }

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function rewrapWithAnyKey(
        string $wrappedSecret,
        iterable|KeyRing $masterSecrets,
        string $newMasterSecret,
        bool $masterSecretsAreBinary = false,
        bool $newMasterSecretIsBinary = false,
    ): string {
        $plaintext = $this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets, $masterSecretsAreBinary)->plaintext;

        return $this->wrap($plaintext, $newMasterSecret, $newMasterSecretIsBinary);
    }

    public function unwrap(string $wrappedSecret, string $masterSecret, bool $masterSecretIsBinary = false): string
    {
        $payload = $this->parseWrappedPayload($wrappedSecret);
        $key = $this->decodeMasterSecret($masterSecret, $masterSecretIsBinary);

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

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function unwrapWithAnyKey(string $wrappedSecret, iterable|KeyRing $masterSecrets, bool $masterSecretsAreBinary = false): string
    {
        return $this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets, $masterSecretsAreBinary)->plaintext;
    }

    /**
     * @param iterable<string, string>|KeyRing $masterSecrets
     */
    public function unwrapWithAnyKeyResult(string $wrappedSecret, iterable|KeyRing $masterSecrets, bool $masterSecretsAreBinary = false): UnwrappedSecretResult
    {
        if ($masterSecrets instanceof KeyRing) {
            $payload = $this->parseWrappedPayload($wrappedSecret);
            if ($payload['key_id'] !== null) {
                $key = $masterSecrets->keys()[$payload['key_id']] ?? null;
                if ($key === null) {
                    throw new SecretProtectionException(sprintf('Master secret key id "%s" was not found in the key ring.', $payload['key_id']));
                }

                try {
                    return new UnwrappedSecretResult(
                        $this->unwrap($wrappedSecret, $key, $masterSecretsAreBinary),
                        $payload['key_id'],
                        false,
                    );
                } catch (SecretProtectionException $e) {
                    throw new SecretProtectionException(
                        sprintf('Secret unwrap failed for key id "%s".', $payload['key_id']),
                        0,
                        $e,
                    );
                }
            }
        }

        $lastException = null;
        foreach ($this->orderedKeyEntries($masterSecrets) as $entry) {
            try {
                return new UnwrappedSecretResult(
                    $this->unwrap($wrappedSecret, $entry['key'], $masterSecretsAreBinary),
                    $entry['id'],
                    !$entry['active'],
                );
            } catch (SecretProtectionException $e) {
                $lastException = $e;
            }
        }

        throw new SecretProtectionException('Secret unwrap failed for every supplied master secret.', 0, $lastException);
    }

    public function unwrapWithKeyRing(string $wrappedSecret, KeyRing $masterSecrets, bool $masterSecretsAreBinary = false): string
    {
        return $this->unwrapWithKeyRingResult($wrappedSecret, $masterSecrets, $masterSecretsAreBinary)->plaintext;
    }

    public function unwrapWithKeyRingResult(string $wrappedSecret, KeyRing $masterSecrets, bool $masterSecretsAreBinary = false): UnwrappedSecretResult
    {
        return $this->unwrapWithAnyKeyResult($wrappedSecret, $masterSecrets, $masterSecretsAreBinary);
    }

    public function wrap(string $secret, string $masterSecret, bool $masterSecretIsBinary = false, ?string $keyId = null): string
    {
        $key = $this->decodeMasterSecret($masterSecret, $masterSecretIsBinary);

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($secret, $nonce, $key);

        return VersionedPayload::encodeCompact(
            WrappedSecretVersion::V1->value,
            self::ALGORITHM_ID,
            $keyId,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
    }

    public function wrapWithKeyRing(string $secret, KeyRing $keyRing, bool $masterSecretIsBinary = false): string
    {
        $activeKey = $keyRing->activeKey();
        $activeKeyId = $keyRing->activeKeyId();
        if ($activeKey === null || $activeKeyId === null) {
            throw new SecretProtectionException('Key ring active key id is required for wrapped secret encryption.');
        }

        return $this->wrap($secret, $activeKey, $masterSecretIsBinary, $activeKeyId);
    }

    private function decodeMasterSecret(string $masterSecret, bool $isBinary): string
    {
        try {
            return BinaryKey::secretBoxKey($masterSecret, $isBinary, 'Master secret');
        } catch (\Throwable $e) {
            throw new SecretProtectionException('Master secret must be 32 bytes long.', 0, $e);
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
                'All master secret candidates must be non-empty strings.',
                'At least one master secret candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new SecretProtectionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array{nonce: string, ciphertext: string, key_id: ?string}
     */
    private function parseWrappedPayload(string $wrappedSecret): array
    {
        $compactPayload = VersionedPayload::parseCompact($wrappedSecret, WrappedSecretVersion::V1->value);
        if ($compactPayload !== null) {
            if ($compactPayload->algorithm !== self::ALGORITHM_ID) {
                throw new SecretProtectionException('Unsupported wrapped secret algorithm.');
            }

            return [
                'nonce' => $compactPayload->nonce,
                'ciphertext' => $compactPayload->ciphertext,
                'key_id' => $compactPayload->keyId,
            ];
        }

        $parsedPayload = VersionedPayload::parse($wrappedSecret, WrappedSecretVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new SecretProtectionException('Invalid wrapped secret format.');
        }

        return [
            'nonce' => $parsedPayload->parts[0],
            'ciphertext' => $parsedPayload->parts[1],
            'key_id' => null,
        ];
    }
}
