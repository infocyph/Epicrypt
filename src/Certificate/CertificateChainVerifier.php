<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CertificateChainVerifier
{
    /**
     * @param list<string> $caCertificatesPem
     */
    public function verify(
        string $certificatePem,
        array $caCertificatesPem,
        CertificatePurpose $purpose = CertificatePurpose::SSL_SERVER,
    ): bool {
        if ($caCertificatesPem === []) {
            throw new ConfigurationException('At least one CA certificate is required for chain verification.');
        }

        $tempCaFiles = [];

        try {
            foreach ($caCertificatesPem as $caCertificatePem) {
                $tempPath = tempnam(sys_get_temp_dir(), 'epicrypt-ca-');
                if ($tempPath === false || file_put_contents($tempPath, $caCertificatePem) === false) {
                    throw new ConfigurationException('Unable to write CA certificate for chain verification.');
                }
                $tempCaFiles[] = $tempPath;
            }

            $result = openssl_x509_checkpurpose($certificatePem, $purpose->value, $tempCaFiles);
            if ($result === false) {
                throw new ConfigurationException('Certificate chain verification failed to execute.');
            }

            return $result === true || $result === 1;
        } finally {
            foreach ($tempCaFiles as $tempCaFile) {
                if (file_exists($tempCaFile)) {
                    unlink($tempCaFile);
                }
            }
        }
    }
}
