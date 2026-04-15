<?php

namespace Infocyph\Epicrypt\Crypto\Signature;

use Infocyph\Epicrypt\Contract\SignerInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Signer implements SignerInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function sign(string $message, mixed $key, array $context = []): string
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Private key must be a non-empty string.');
        }

        $privateKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKeyException('Private key has invalid length.');
        }

        $signature = sodium_crypto_sign_detached($message, $privateKey);
        if (! is_string($signature)) {
            throw new SignatureException('Failed to sign message.');
        }

        return Base64Url::encode($signature);
    }
}
