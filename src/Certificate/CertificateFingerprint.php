<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Enum\CertificateDigest;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateFingerprint
{
    public function fingerprint(
        string $certificatePem,
        CertificateDigest $algorithm = CertificateDigest::SHA256,
    ): string {
        $der = $this->pemToDer($certificatePem);

        return hash($algorithm->value, $der);
    }

    private function pemToDer(string $certificatePem): string
    {
        $normalized = preg_replace('/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/', '', $certificatePem);
        if (!is_string($normalized) || $normalized === '') {
            throw new ConfigurationException('Invalid certificate PEM content.');
        }

        $der = base64_decode($normalized, true);
        if (!is_string($der) || $der === '') {
            throw new ConfigurationException('Unable to decode certificate PEM.');
        }

        return $der;
    }
}
