<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class DiffieHellman implements KeyExchangeInterface
{
    public function deriveSharedSecret(string $privateKey, string $publicKey, bool $keysAreBinary): string
    {
        $private = Pem::decodeIfEncoded($privateKey, !$keysAreBinary);
        $public = Pem::decodeIfEncoded($publicKey, !$keysAreBinary);

        $privateResource = Pem::requirePrivateKeyResource($private);
        $publicResource = Pem::requirePublicKeyResource($public);

        $secret = openssl_pkey_derive($publicResource, $privateResource);
        if (!is_string($secret) || $secret === '') {
            throw new ConfigurationException('OpenSSL key exchange failed.');
        }

        return $secret;
    }
}
