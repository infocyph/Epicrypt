<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class DiffieHellman implements KeyExchangeInterface
{
    public function deriveSharedSecret(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
    ): string {
        return $this->derive($privateKey, $publicKey);
    }

    public function deriveSharedSecretFromBinaryKeys(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
    ): string {
        return $this->derive(
            $this->derToPem($privateKey, 'PRIVATE KEY'),
            $this->derToPem($publicKey, 'PUBLIC KEY'),
        );
    }

    private function derive(
        #[\SensitiveParameter]
        string $privateKey,
        string $publicKey,
    ): string {
        $private = $privateKey;
        $public = $publicKey;

        $privateResource = Pem::requirePrivateKeyResource($private);
        $publicResource = Pem::requirePublicKeyResource($public);

        $secret = openssl_pkey_derive($publicResource, $privateResource);
        if (!is_string($secret) || $secret === '') {
            throw new ConfigurationException('OpenSSL key exchange failed.');
        }

        return $secret;
    }

    private function derToPem(#[\SensitiveParameter] string $key, string $label): string
    {
        if ($key === '') {
            throw new ConfigurationException('Binary OpenSSL key material must not be empty.');
        }

        return sprintf("-----BEGIN %s-----\n%s-----END %s-----\n", $label, chunk_split(base64_encode($key), 64, "\n"), $label);
    }
}
