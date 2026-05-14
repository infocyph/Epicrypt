<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Contract\CertificateAuthorityInterface;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslCertificateSigner;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslExtensionConfig;
use Infocyph\Epicrypt\Certificate\Support\Pem;

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
            return OpenSslCertificateSigner::signAndExport(
                $csrPem,
                $caCertificatePem,
                $caKeyResource,
                $options->days,
                $config,
                'CA certificate signing failed.',
                'Signed certificate export failed.',
            );
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }
}
