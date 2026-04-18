<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Enum\WrappedSecretVersion;
use Infocyph\Epicrypt\Internal\KeyCandidates;
use Infocyph\Epicrypt\Internal\VersionedPayload;
use Infocyph\Epicrypt\Security\KeyRing;

final class WrappedSecretManager
{
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
    public function rewrapWithAny(
        string $wrappedSecret,
        iterable|KeyRing $masterSecrets,
        string $newMasterSecret,
        bool $masterSecretsAreBinary = false,
        bool $newMasterSecretIsBinary = false,
    ): string {
        $plaintext = $this->unwrapWithAny($wrappedSecret, $masterSecrets, $masterSecretsAreBinary);

        return $this->wrap($plaintext, $newMasterSecret, $newMasterSecretIsBinary);
    }

    public function unwrap(string $wrappedSecret, string $masterSecret, bool $masterSecretIsBinary = false): string
    {
        [$encodedNonce, $encodedCipher] = $this->splitWrappedSecret($wrappedSecret);
        $key = $masterSecretIsBinary ? $masterSecret : Base64Url::decode($masterSecret);

        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SecretProtectionException('Master secret must be 32 bytes long.');
        }

        $plaintext = sodium_crypto_secretbox_open(
            Base64Url::decode($encodedCipher),
            Base64Url::decode($encodedNonce),
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
    public function unwrapWithAny(string $wrappedSecret, iterable|KeyRing $masterSecrets, bool $masterSecretsAreBinary = false): string
    {
        $lastException = null;
        foreach ($this->orderedKeys($masterSecrets) as $masterSecret) {
            try {
                return $this->unwrap($wrappedSecret, $masterSecret, $masterSecretsAreBinary);
            } catch (SecretProtectionException $e) {
                $lastException = $e;
            }
        }

        throw new SecretProtectionException('Secret unwrap failed for every supplied master secret.', 0, $lastException);
    }

    public function wrap(string $secret, string $masterSecret, bool $masterSecretIsBinary = false): string
    {
        $key = $masterSecretIsBinary ? $masterSecret : Base64Url::decode($masterSecret);
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SecretProtectionException('Master secret must be 32 bytes long.');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($secret, $nonce, $key);

        return VersionedPayload::encode(
            WrappedSecretVersion::V1->value,
            Base64Url::encode($nonce),
            Base64Url::encode($ciphertext),
        );
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
                'All master secret candidates must be non-empty strings.',
                'At least one master secret candidate is required.',
            );
        } catch (\InvalidArgumentException $e) {
            throw new SecretProtectionException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @return array{string, string}
     */
    private function splitWrappedSecret(string $wrappedSecret): array
    {
        $parsedPayload = VersionedPayload::parse($wrappedSecret, WrappedSecretVersion::V1->value, 2);
        if ($parsedPayload === null) {
            throw new SecretProtectionException('Invalid wrapped secret format.');
        }
        [, $parts] = $parsedPayload;

        return [$parts[0], $parts[1]];
    }
}
