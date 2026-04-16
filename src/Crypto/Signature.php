<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\SignatureInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Signature implements SignatureInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function sign(string $message, mixed $key, array $context = []): string
    {
        if (!is_string($key) || $key === '') {
            throw new InvalidKeyException('Private key must be a non-empty string.');
        }

        $privateKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new InvalidKeyException('Private key has invalid length.');
        }

        $signature = sodium_crypto_sign_detached($message, $privateKey);

        return Base64Url::encode($signature);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool
    {
        if (!is_string($key) || $key === '') {
            throw new InvalidKeyException('Public key must be a non-empty string.');
        }

        $publicKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException('Public key has invalid length.');
        }

        $decodedSignature = Base64Url::decode($signature);
        if ($decodedSignature === '') {
            throw new SignatureException('Signature must decode to non-empty bytes.');
        }

        return sodium_crypto_sign_verify_detached($decodedSignature, $message, $publicKey);
    }
}
