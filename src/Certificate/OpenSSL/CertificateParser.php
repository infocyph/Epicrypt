<?php

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\CertificateParserInterface;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateParser implements CertificateParserInterface
{
    /**
     * @return array<string, mixed>
     */
    public function parse(string $certificatePem): array
    {
        $parsed = openssl_x509_parse($certificatePem, false);
        if (! is_array($parsed)) {
            throw new ConfigurationException('Certificate parsing failed.');
        }

        return $parsed;
    }
}
