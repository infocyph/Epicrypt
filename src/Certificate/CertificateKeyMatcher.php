<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateKeyMatcher
{
    public function privateKeyMatches(
        string $certificatePem,
        #[\SensitiveParameter]
        string $privateKeyPem,
        #[\SensitiveParameter]
        ?string $passphrase = null,
    ): bool {
        $privateKey = openssl_pkey_get_private($privateKeyPem, $passphrase ?? '');
        if ($privateKey === false) {
            throw new ConfigurationException('Unable to load private key.');
        }

        $certificatePublicKey = openssl_pkey_get_public($certificatePem);
        if ($certificatePublicKey === false) {
            throw new ConfigurationException('Unable to load certificate public key.');
        }

        $privateDetails = openssl_pkey_get_details($privateKey);
        $publicDetails = openssl_pkey_get_details($certificatePublicKey);
        if (!is_array($privateDetails) || !is_array($publicDetails)) {
            throw new ConfigurationException('Unable to read key details.');
        }

        return isset($privateDetails['key'], $publicDetails['key'])
            && is_string($privateDetails['key'])
            && is_string($publicDetails['key'])
            && hash_equals($privateDetails['key'], $publicDetails['key']);
    }
}
