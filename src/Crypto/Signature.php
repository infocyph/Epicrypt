<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Crypto\Contract\SignatureInterface;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class Signature implements SignatureInterface
{
    /**
     * @param array<string, mixed> $context
     */
    public function sign(string $message, mixed $key, array $context = []): string
    {
        try {
            $privateKey = BinaryKey::signSecretKey($key, (bool) ($context['key_is_binary'] ?? false), 'Private key');
        } catch (InvalidKeyException $e) {
            throw new SignatureException('Private key must be a valid signing secret key.', 0, $e);
        }

        $signature = sodium_crypto_sign_detached($message, $this->requireNonEmptyKey($privateKey, 'Private key'));

        return Base64Url::encode($signature);
    }

    /**
     * @param array<string, mixed> $context
     */
    public function verify(string $message, string $signature, mixed $key, array $context = []): bool
    {
        try {
            $publicKey = BinaryKey::signPublicKey($key, (bool) ($context['key_is_binary'] ?? false), 'Public key');
        } catch (InvalidKeyException $e) {
            throw new SignatureException('Public key must be a valid signing public key.', 0, $e);
        }

        $decodedSignature = Base64Url::decode($signature);
        if ($decodedSignature === '') {
            throw new SignatureException('Signature must decode to non-empty bytes.');
        }

        return sodium_crypto_sign_verify_detached($decodedSignature, $message, $this->requireNonEmptyKey($publicKey, 'Public key'));
    }

    /**
     * @return non-empty-string
     */
    private function requireNonEmptyKey(string $key, string $label): string
    {
        if ($key === '') {
            throw new SignatureException($label . ' must not be empty.');
        }

        return $key;
    }
}
