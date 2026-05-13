<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Contract\CertificateBuilderInterface;
use Infocyph\Epicrypt\Certificate\OpenSSL\Support\OpenSslExtensionConfig;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class CertificateBuilder implements CertificateBuilderInterface
{
    public function __construct(
        private string $digestAlgorithm = 'sha512',
    ) {}

    /**
     * @param array<string, string> $distinguishedName
     */
    public function selfSign(array $distinguishedName, string $privateKey, int $days = 365, ?string $passphrase = null, ?CertificateOptions $options = null): string
    {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);
        $effectiveOptions = $options ?? new CertificateOptions(days: $days, digestAlgorithm: $this->digestAlgorithm);
        $requestedDays = $effectiveOptions->days;
        $digestAlgorithm = $effectiveOptions->digestAlgorithm;
        $tempConfigPath = OpenSslExtensionConfig::createTempConfig($effectiveOptions);
        $csrConfig = ['digest_alg' => $digestAlgorithm];
        $signConfig = ['digest_alg' => $digestAlgorithm];
        $csrConfig['config'] = $tempConfigPath;
        $csrConfig['req_extensions'] = 'v3_req';
        $signConfig['config'] = $tempConfigPath;
        $signConfig['x509_extensions'] = 'v3_req';

        try {
            $csr = openssl_csr_new($distinguishedName, $privateResource, $csrConfig);
            if (!$csr instanceof \OpenSSLCertificateSigningRequest) {
                throw new ConfigurationException('CSR generation failed for certificate signing.');
            }

            $signingPrivateKey = $passphrase === null ? $privateKey : [$privateKey, $passphrase];

            $certificate = openssl_csr_sign($csr, null, $signingPrivateKey, $requestedDays, $signConfig);
            if ($certificate === false) {
                throw new ConfigurationException('Certificate signing failed.');
            }

            $exported = openssl_x509_export($certificate, $certificatePem);
            if (!$exported || !is_string($certificatePem) || $certificatePem === '') {
                throw new ConfigurationException('Certificate export failed.');
            }

            return $certificatePem;
        } finally {
            if (file_exists($tempConfigPath)) {
                unlink($tempConfigPath);
            }
        }
    }
}
