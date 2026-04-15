<?php

namespace Infocyph\Epicrypt\Crypto\Auth;

use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class MacGenerator
{
    public function generate(string $message, string $key, bool $keyIsBinary = false): string
    {
        $decodedKey = $keyIsBinary ? $key : Base64Url::decode($key);

        if (strlen($decodedKey) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new CryptoException('MAC key must be 32 bytes.');
        }

        return Base64Url::encode(sodium_crypto_auth($message, $decodedKey));
    }

    public function generateKey(bool $asBase64Url = true): string
    {
        $key = sodium_crypto_auth_keygen();

        return $asBase64Url ? Base64Url::encode($key) : $key;
    }
}
