<?php

namespace Infocyph\Epicrypt\Crypto\Auth;

use Infocyph\Epicrypt\Exception\Crypto\CryptoException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class MacVerifier
{
    public function verify(string $message, string $mac, string $key, bool $keyIsBinary = false): bool
    {
        $decodedKey = $keyIsBinary ? $key : Base64Url::decode($key);
        if (strlen($decodedKey) !== SODIUM_CRYPTO_AUTH_KEYBYTES) {
            throw new CryptoException('MAC key must be 32 bytes.');
        }

        return sodium_crypto_auth_verify(Base64Url::decode($mac), $message, $decodedKey);
    }
}
