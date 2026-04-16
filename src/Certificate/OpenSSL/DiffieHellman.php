<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\KeyExchangeInterface;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

final class DiffieHellman implements KeyExchangeInterface
{
    public function derive(string $privateKey, string $publicKey, bool $keysAreBinary = false): string
    {
        $private = Pem::decodeIfEncoded($privateKey, !$keysAreBinary);
        $public = Pem::decodeIfEncoded($publicKey, !$keysAreBinary);

        $privateResource = Pem::requirePrivateKeyResource($private);
        $publicResource = Pem::requirePublicKeyResource($public);

        $secret = openssl_pkey_derive($publicResource, $privateResource, 32);
        if (!is_string($secret) || $secret === '') {
            throw new ConfigurationException('OpenSSL key exchange failed.');
        }

        return $keysAreBinary ? $secret : Base64Url::encode($secret);
    }
}
