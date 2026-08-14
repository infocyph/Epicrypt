<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslExtensionConfig;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CsrBuilder
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function build(
        array $distinguishedName,
        #[\SensitiveParameter]
        string $privateKey,
        #[\SensitiveParameter]
        ?string $passphrase = null,
        ?CertificateOptions $options = null,
    ): string {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);
        $effectiveOptions = $options ?? new CertificateOptions();
        $tempConfigPath = OpenSslExtensionConfig::createTempConfig($effectiveOptions, $distinguishedName);
        $config = ['digest_alg' => $effectiveOptions->digestAlgorithm->value];
        $config['config'] = $tempConfigPath;
        $config['req_extensions'] = 'v3_req';

        try {
            $csr = openssl_csr_new($distinguishedName, $privateResource, $config);
            if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
                throw new ConfigurationException('CSR generation failed.');
            }

            $exported = openssl_csr_export($csr, $csrPem);
            if (!$exported || !is_string($csrPem) || $csrPem === '') {
                throw new ConfigurationException('CSR export failed.');
            }

            return $csrPem;
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }
}
