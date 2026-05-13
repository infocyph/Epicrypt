<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Contract\CertificateAuthorityInterface;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslExtensionConfig;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateAuthority implements CertificateAuthorityInterface
{
    public function signCsr(
        string $csrPem,
        string $caCertificatePem,
        string $caPrivateKeyPem,
        CertificateOptions $options,
        ?string $passphrase = null,
    ): string {
        $caKeyResource = Pem::requirePrivateKeyResource($caPrivateKeyPem, $passphrase);
        $tempConfigPath = OpenSslExtensionConfig::createTempConfig($options);
        $config = ['digest_alg' => $options->digestAlgorithm];
        $config['config'] = $tempConfigPath;
        $config['x509_extensions'] = 'v3_req';

        try {
            $certificate = openssl_csr_sign(
                $csrPem,
                $caCertificatePem,
                $caKeyResource,
                $options->days,
                $config,
            );
            if ($certificate === false) {
                throw new ConfigurationException('CA certificate signing failed.');
            }

            $exported = openssl_x509_export($certificate, $certificatePem);
            if (!$exported || !is_string($certificatePem) || $certificatePem === '') {
                throw new ConfigurationException('Signed certificate export failed.');
            }

            return $certificatePem;
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }
}
