<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\SignatureInterface;
use Infocyph\Epicrypt\Crypto\Support\KeyDecoder;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Signature implements SignatureInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function sign(string $message, mixed $key, array $context = []): string
    {
        $privateKey = KeyDecoder::decode(
            $key,
            (bool) ($context['key_is_binary'] ?? false),
            SODIUM_CRYPTO_SIGN_SECRETKEYBYTES,
            'Private key',
        );

        $signature = sodium_crypto_sign_detached($message, $privateKey);

        return Base64Url::encode($signature);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool
    {
        $publicKey = KeyDecoder::decode(
            $key,
            (bool) ($context['key_is_binary'] ?? false),
            SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,
            'Public key',
        );

        $decodedSignature = Base64Url::decode($signature);
        if ($decodedSignature === '') {
            throw new SignatureException('Signature must decode to non-empty bytes.');
        }

        return sodium_crypto_sign_verify_detached($decodedSignature, $message, $publicKey);
    }
}
