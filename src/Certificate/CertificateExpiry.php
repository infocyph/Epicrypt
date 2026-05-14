<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateExpiry
{
    public function expiresAt(string $certificatePem): int
    {
        $parsed = openssl_x509_parse($certificatePem, false);
        if (!is_array($parsed) || !isset($parsed['validTo_time_t']) || !is_int($parsed['validTo_time_t'])) {
            throw new ConfigurationException('Unable to parse certificate expiration.');
        }

        return $parsed['validTo_time_t'];
    }

    public function isExpired(string $certificatePem, int $leewaySeconds = 0): bool
    {
        return time() + $leewaySeconds >= $this->expiresAt($certificatePem);
    }
}
