<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Sodium;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class SessionKeyExchange implements KeyExchangeInterface
{
    public function deriveSharedSecret(string $privateKey, string $publicKey, bool $keysAreBinary): string
    {
        try {
            $private = BinaryKey::fixedLength($privateKey, $keysAreBinary, SODIUM_CRYPTO_BOX_SECRETKEYBYTES, 'Private key');
            $public = BinaryKey::fixedLength($publicKey, $keysAreBinary, SODIUM_CRYPTO_BOX_PUBLICKEYBYTES, 'Public key');
        } catch (InvalidKeyException $e) {
            throw new InvalidKeyException('Sodium key exchange requires valid curve25519 private/public keys.', 0, $e);
        }

        return sodium_crypto_scalarmult($private, $public);
    }
}
