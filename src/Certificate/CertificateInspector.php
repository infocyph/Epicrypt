<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use phpseclib4\File\X509;
use Throwable;

final readonly class CertificateInspector
{
    private const int MAX_CERTIFICATE_BYTES = 1_048_576;

    /** @return array{subject: string, issuer: string, public_key: string, extensions: list<string>} */
    public function inspect(string $certificatePem): array
    {
        if ($certificatePem === '' || strlen($certificatePem) > self::MAX_CERTIFICATE_BYTES) {
            throw new ConfigurationException('Certificate is empty or exceeds the configured size bound.');
        }

        try {
            $certificate = X509::load($certificatePem);
            $subject = $certificate->getSubjectDN(X509::DN_STRING);
            $issuer = $certificate->getIssuerDN(X509::DN_STRING);
            $extensions = $certificate->listExtensions();
            $publicKey = $certificate->getPublicKey()->toString('PKCS8');
        } catch (Throwable $exception) {
            throw new ConfigurationException('Certificate parsing failed.', 0, $exception);
        }
        if (!is_string($subject) || !is_string($issuer)) {
            throw new ConfigurationException('Certificate distinguished names are invalid.');
        }

        $normalizedExtensions = [];
        foreach ($extensions as $extension) {
            if (is_string($extension)) {
                $normalizedExtensions[] = $extension;
            }
        }

        return [
            'subject' => $subject,
            'issuer' => $issuer,
            'public_key' => $publicKey,
            'extensions' => array_values(array_unique($normalizedExtensions)),
        ];
    }
}
