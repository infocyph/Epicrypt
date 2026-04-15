<?php

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Exception\Password\SecretProtectionException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class WrappedSecretManager
{
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
    public function wrap(string $secret, string $masterSecret, bool $masterSecretIsBinary = false): string
    {
        $key = $masterSecretIsBinary ? $masterSecret : Base64Url::decode($masterSecret);
        if (strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new SecretProtectionException('Master secret must be 32 bytes long.');
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($secret, $nonce, $key);

        return Base64Url::encode($nonce) . '.' . Base64Url::encode($ciphertext);
    }

    /**
     * @return array{string, string}
     */
    private function splitWrappedSecret(string $wrappedSecret): array
    {
        $parts = explode('.', $wrappedSecret, 2);
        if (count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            throw new SecretProtectionException('Invalid wrapped secret format.');
        }

        return [$parts[0], $parts[1]];
    }
}
