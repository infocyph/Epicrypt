<?php

namespace Infocyph\Epicrypt\Certificate\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;

/**
 * @internal
 */
final class Pem
{
    public static function decodeIfEncoded(string $value, bool $isBase64Url): string
    {
        return $isBase64Url ? Base64Url::decode($value) : $value;
    }

    public static function requirePrivateKeyResource(string $privateKey, ?string $passphrase = null): \OpenSSLAsymmetricKey
    {
        $resource = openssl_pkey_get_private($privateKey, $passphrase ?? '');
        if ($resource === false) {
            throw new ConfigurationException('Unable to load private key.');
        }

        return $resource;
    }

    public static function requirePublicKeyResource(string $publicKey): \OpenSSLAsymmetricKey
    {
        $resource = openssl_pkey_get_public($publicKey);
        if ($resource === false) {
            throw new ConfigurationException('Unable to load public key.');
        }

        return $resource;
    }
}
