<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Crypto;

use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;
use Infocyph\Epicrypt\Exception\Crypto\SignatureException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\BinaryKey;

final class Signature
{
    public function sign(string $message, #[\SensitiveParameter] string $key): string
    {
        try {
            return $this->signWithBinaryKey($message, Base64Url::decode($key));
        } catch (SignatureException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new SignatureException('Private key must be a valid signing secret key.', 0, $exception);
        }
    }

    public function signWithBinaryKey(string $message, #[\SensitiveParameter] string $key): string
    {
        try {
            $privateKey = BinaryKey::fixedLength($key, true, SODIUM_CRYPTO_SIGN_SECRETKEYBYTES, 'Private key');
        } catch (InvalidKeyException $e) {
            throw new SignatureException('Private key must be a valid signing secret key.', 0, $e);
        }

        $signature = sodium_crypto_sign_detached($message, $this->requireNonEmptyKey($privateKey, 'Private key'));

        return Base64Url::encode($signature);
    }

    public function verify(string $message, string $signature, string $key): bool
    {
        try {
            return $this->verifyWithBinaryKey($message, $signature, Base64Url::decode($key));
        } catch (SignatureException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new SignatureException('Public key must be a valid signing public key.', 0, $exception);
        }
    }

    public function verifyWithBinaryKey(string $message, string $signature, string $key): bool
    {
        try {
            $publicKey = BinaryKey::fixedLength($key, true, SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES, 'Public key');
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
