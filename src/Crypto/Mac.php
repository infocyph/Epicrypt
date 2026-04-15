<?php

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Mac
{
    public function generate(string $message, string $key, bool $keyIsBinary = false): string
    {
        $decodedKey = $this->decodeKey($key, $keyIsBinary);

        return Base64Url::encode(sodium_crypto_auth($message, $decodedKey));
    }

    public function generateKey(bool $asBase64Url = true): string
    {
        $key = sodium_crypto_auth_keygen();

        return $asBase64Url ? Base64Url::encode($key) : $key;
    }

    public function verify(string $message, string $mac, string $key, bool $keyIsBinary = false): bool
    {
        $decodedKey = $this->decodeKey($key, $keyIsBinary);

        return sodium_crypto_auth_verify(Base64Url::decode($mac), $message, $decodedKey);
    }

    private function decodeKey(string $key, bool $isBinary): string
    {
        $decodedKey = $isBinary ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new CryptoException('MAC key must be 32 bytes.');
        }

        return $decodedKey;
    }
}
