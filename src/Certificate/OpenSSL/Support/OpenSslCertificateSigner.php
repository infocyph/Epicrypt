<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL\Support;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final class OpenSslCertificateSigner
{
    /**
     * @param array<string, mixed> $config
     * @param array{0: string, 1: string}|\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $caPrivateKey
     */
    public static function signAndExport(
        \OpenSSLCertificateSigningRequest|string $csr,
        \OpenSSLCertificate|string|null $caCertificate,
        #[\SensitiveParameter]
        array|\OpenSSLAsymmetricKey|\OpenSSLCertificate|string $caPrivateKey,
        int $days,
        array $config,
        string $signErrorMessage,
        string $exportErrorMessage,
    ): string {
        $certificate = openssl_csr_sign($csr, $caCertificate, $caPrivateKey, $days, $config);
        if ($certificate === false) {
            throw new ConfigurationException($signErrorMessage);
        }

        $exported = openssl_x509_export($certificate, $certificatePem);
        if (!$exported || !is_string($certificatePem) || $certificatePem === '') {
            throw new ConfigurationException($exportErrorMessage);
        }

        return $certificatePem;
    }
}
