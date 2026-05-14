<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\Crypto\DecryptionException;
use Infocyph\Epicrypt\Exception\Crypto\EncryptionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use OpenSSLAsymmetricKey;

/**
 * Compatibility-focused RSA helper.
 * Use envelope encryption for large payloads and modern data-at-rest flows.
 */
final class RsaCipher
{
    public function decrypt(string $ciphertext, string $privateKey, ?string $passphrase = null): string
    {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);
        $decoded = Base64Url::decode($ciphertext);

        return $this->run(
            static fn(string $input, mixed &$output, OpenSSLAsymmetricKey $resource): bool => openssl_private_decrypt(
                $input,
                $output,
                $resource,
                OPENSSL_PKCS1_OAEP_PADDING,
            ),
            $decoded,
            $privateResource,
            new DecryptionException('RSA decryption failed.'),
        );
    }

    public function encrypt(string $plaintext, string $publicKey): string
    {
        $publicResource = Pem::requirePublicKeyResource($publicKey);

        $encrypted = $this->run(
            static fn(string $input, mixed &$output, OpenSSLAsymmetricKey $resource): bool => openssl_public_encrypt(
                $input,
                $output,
                $resource,
                OPENSSL_PKCS1_OAEP_PADDING,
            ),
            $plaintext,
            $publicResource,
            new EncryptionException('RSA encryption failed.'),
        );

        return Base64Url::encode($encrypted);
    }

    /**
     * @param callable(string, mixed&, OpenSSLAsymmetricKey): bool $operation
     */
    private function run(
        callable $operation,
        string $input,
        OpenSSLAsymmetricKey $resource,
        \RuntimeException $exception,
    ): string {
        $output = '';
        $ok = $operation($input, $output, $resource);
        if (!$ok || !is_string($output)) {
            throw $exception;
        }

        return $output;
    }
}
