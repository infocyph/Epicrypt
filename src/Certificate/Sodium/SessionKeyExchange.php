<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class SessionKeyExchange implements KeyExchangeInterface
{
    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string
    {
        try {
            $private = BinaryKey::fixedLength($privateKey, $keysAreBinary, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'Private key');
            $public = BinaryKey::fixedLength($publicKey, $keysAreBinary, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Public key');
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException('Sodium key exchange requires valid curve25519 private/public keys.', 0, $e);
        }

        $secret = sodium_crypto_scalarmult($private, $public);

        return $keysAreBinary ? $secret : Base64Url::encode($secret);
    }
}
