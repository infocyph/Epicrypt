<?php

namespace Infocyph\Epicrypt\Crypto\Signature;

use Infocyph\Epicrypt\Contract\VerifierInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class Verifier implements VerifierInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool
    {
        if (! is_string($key) || $key === '') {
            throw new InvalidKeyException('Public key must be a non-empty string.');
        }

        $publicKey = (bool) ($context['key_is_binary'] ?? false) ? $key : Base64Url::decode($key);
        if (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new InvalidKeyException('Public key has invalid length.');
        }

        return sodium_crypto_sign_verify_detached(Base64Url::decode($signature), $message, $publicKey);
    }
}
