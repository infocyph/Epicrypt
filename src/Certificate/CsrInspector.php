<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use phpseclib4\File\CSR;
use Throwable;

final readonly class CsrInspector
{
    private const int MAX_CSR_BYTES = 1_048_576;

    /** @return array{subject: string, public_key: string, extensions: list<string>} */
    public function inspect(string $csrPem): array
    {
        if ($csrPem === '' || strlen($csrPem) > self::MAX_CSR_BYTES) {
            throw new ConfigurationException('CSR is empty or exceeds the configured size bound.');
        }

        try {
            $csr = CSR::load($csrPem);
            if (!$csr->validateSignature()) {
                throw new ConfigurationException('CSR signature is invalid.');
            }
            $subject = $csr->getSubjectDN(CSR::DN_STRING);
            $extensions = $csr->listExtensions();
            $publicKey = $csr->getPublicKey()->toString('PKCS8');
        } catch (ConfigurationException $exception) {
            throw $exception;
        } catch (Throwable $exception) {
            throw new ConfigurationException('CSR parsing failed.', 0, $exception);
        }
        if (!is_string($subject)) {
            throw new ConfigurationException('CSR subject is invalid.');
        }

        $normalizedExtensions = [];
        foreach ($extensions as $extension) {
            if (is_string($extension)) {
                $normalizedExtensions[] = $extension;
            }
        }

        return [
            'subject' => $subject,
            'public_key' => $publicKey,
            'extensions' => array_values(array_unique($normalizedExtensions)),
        ];
    }
}
