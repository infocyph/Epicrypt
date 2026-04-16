<?php

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class SessionKeyExchange implements KeyExchangeInterface
{
    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string
    {
        $private = $keysAreBinary ? $privateKey : Base64Url::decode($privateKey);
        $public = $keysAreBinary ? $publicKey : Base64Url::decode($publicKey);

        if (strlen($private) !== SODIUM_CRYPTO_BOX_SECRETKEYBYTES || strlen($public) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new InvalidKeyException('Sodium key exchange requires valid curve25519 private/public keys.');
        }

        $secret = sodium_crypto_scalarmult($private, $public);

        return $keysAreBinary ? $secret : Base64Url::encode($secret);
    }
}
