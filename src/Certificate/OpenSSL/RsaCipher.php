<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class RsaCipher
{
    public function decrypt(string $ciphertext, string $privateKey, ?string $passphrase = null): string
    {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);
        $decoded = Base64Url::decode($ciphertext);

        $decrypted = null;
        $ok = openssl_private_decrypt($decoded, $decrypted, $privateResource, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok || !is_string($decrypted)) {
            throw new DecryptionException('RSA decryption failed.');
        }

        return $decrypted;
    }

    public function encrypt(string $plaintext, string $publicKey): string
    {
        $publicResource = Pem::requirePublicKeyResource($publicKey);

        $encrypted = null;
        $ok = openssl_public_encrypt($plaintext, $encrypted, $publicResource, OPENSSL_PKCS1_OAEP_PADDING);
        if (!$ok || !is_string($encrypted)) {
            throw new EncryptionException('RSA encryption failed.');
        }

        return Base64Url::encode($encrypted);
    }
}
