<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;

/** @internal X.509/JWK binding boundary shared by JWKS operations. */
final class JwkCertificateBinding
{
    /**
     * @param array<string, mixed> $jwk
     * @param list<string> $certificateChainPem
     * @return array<string, mixed>
     */
    public function bind(array $jwk, array $certificateChainPem): array
    {
        if ($certificateChainPem === []) {
            throw new KeyResolutionException('A certificate chain must not be empty.');
        }
        $encodedChain = [];
        foreach ($certificateChainPem as $certificate) {
            $encodedChain[] = base64_encode($this->certificateDer($certificate));
        }
        $leaf = base64_decode($encodedChain[0], true);
        if (!is_string($leaf)) {
            throw new KeyResolutionException('Unable to encode leaf certificate.');
        }
        $jwk['x5c'] = $encodedChain;
        $jwk['x5t'] = Base64Url::encode(hash('sha1', $leaf, true));
        $jwk['x5t#S256'] = Base64Url::encode(hash('sha256', $leaf, true));

        return $jwk;
    }

    /** @param array<string, mixed> $jwk */
    public function validate(array $jwk, string $jwkPublicKey): void
    {
        $leaf = $this->leafCertificate($jwk);
        $this->validateThumbprint($jwk, 'x5t', 'sha1', $leaf);
        $this->validateThumbprint($jwk, 'x5t#S256', 'sha256', $leaf);

        $certificatePem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($leaf), 64, "\n") . "-----END CERTIFICATE-----\n";
        $certificateKey = openssl_pkey_get_public($certificatePem);
        $jwkKey = openssl_pkey_get_public($jwkPublicKey);
        $certificateDetails = $certificateKey === false ? false : openssl_pkey_get_details($certificateKey);
        $jwkDetails = $jwkKey === false ? false : openssl_pkey_get_details($jwkKey);
        if (!is_array($certificateDetails) || !is_array($jwkDetails)
            || !is_string($certificateDetails['key'] ?? null) || !is_string($jwkDetails['key'] ?? null)
            || !hash_equals($certificateDetails['key'], $jwkDetails['key'])) {
            throw new KeyResolutionException('JWK public key does not match the leaf certificate.');
        }
    }

    private function certificateDer(string $certificatePem): string
    {
        $der = $this->decodeCertificatePem($certificatePem);
        $certificate = openssl_x509_read($certificatePem);
        $normalized = '';
        if ($certificate === false || !openssl_x509_export($certificate, $normalized) || !is_string($normalized)) {
            throw new KeyResolutionException('Unable to read certificate for JWK binding.');
        }

        return $der;
    }

    private function decodeCertificatePem(string $certificatePem): string
    {
        if (preg_match(
            '/\A-----BEGIN CERTIFICATE-----\R([A-Za-z0-9+\/=\r\n]+)-----END CERTIFICATE-----\R?\z/',
            $certificatePem,
            $matches,
        ) !== 1) {
            throw new KeyResolutionException('Unable to read certificate for JWK binding.');
        }
        $body = preg_replace('/\s+/', '', $matches[1]);
        $der = is_string($body) ? base64_decode($body, true) : false;
        if (!is_string($der) || $der === '') {
            throw new KeyResolutionException('Unable to encode certificate for JWK binding.');
        }

        return $der;
    }

    /** @param array<string, mixed> $jwk */
    private function leafCertificate(array $jwk): string
    {
        $chain = $jwk['x5c'] ?? null;
        if (!is_array($chain) || $chain === [] || !array_is_list($chain) || !is_string($chain[0])) {
            throw new KeyResolutionException('JWK x5c must be a non-empty certificate list.');
        }
        foreach ($chain as $certificate) {
            $der = is_string($certificate) ? base64_decode($certificate, true) : false;
            if (!is_string($der) || $der === '') {
                throw new KeyResolutionException('JWK x5c contains an invalid certificate.');
            }
            $pem = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
            if (openssl_x509_read($pem) === false) {
                throw new KeyResolutionException('JWK x5c contains an unparseable certificate.');
            }
        }
        $leaf = base64_decode($chain[0], true);
        if (!is_string($leaf) || $leaf === '') {
            throw new KeyResolutionException('JWK x5c leaf certificate is invalid.');
        }

        return $leaf;
    }

    /** @param array<string, mixed> $jwk */
    private function validateThumbprint(array $jwk, string $name, string $hash, string $leaf): void
    {
        if (!isset($jwk[$name])) {
            return;
        }
        if (!is_string($jwk[$name]) || !hash_equals(Base64Url::encode(hash($hash, $leaf, true)), $jwk[$name])) {
            throw new KeyResolutionException(sprintf('JWK %s does not match the leaf certificate.', $name));
        }
    }
}
