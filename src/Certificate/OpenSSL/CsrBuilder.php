<?php

namespace Infocyph\Epicrypt\Certificate\OpenSSL;

use Infocyph\Epicrypt\Certificate\Contract\CsrBuilderInterface;
use Infocyph\Epicrypt\Certificate\Support\Pem;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final class CsrBuilder implements CsrBuilderInterface
{
    /**
     * @param array<string, string> $distinguishedName
     */
    public function build(array $distinguishedName, string $privateKey, ?string $passphrase = null): string
    {
        $privateResource = Pem::requirePrivateKeyResource($privateKey, $passphrase);

        $csr = openssl_csr_new($distinguishedName, $privateResource, ['digest_alg' => 'sha512']);
        if ($csr === false) {
            throw new ConfigurationException('CSR generation failed.');
        }

        $exported = openssl_csr_export($csr, $csrPem);
        if (! $exported || ! is_string($csrPem) || $csrPem === '') {
            throw new ConfigurationException('CSR export failed.');
        }

        return $csrPem;
    }
}
