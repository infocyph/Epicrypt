<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\HashAlgorithm;

final class CertificateFingerprint
{
    public function fingerprint(string $certificatePem, string $algorithm = 'sha256'): string
    {
        try {
            HashAlgorithm::assertSupported($algorithm);
        } catch (\InvalidArgumentException $e) {
            throw new ConfigurationException($e->getMessage(), 0, $e);
        }

        $der = $this->pemToDer($certificatePem);

        return hash($algorithm, $der);
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
