<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
use Infocyph\Epicrypt\Certificate\CertificateInspector;
use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\CsrInspector;
use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;
use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateAuthority;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\OpenSSL\CsrBuilder;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('parses OpenSSL certificates and CSRs through phpseclib 4 boundaries', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $options = new CertificateOptions(
        days: 30,
        sanDns: ['inspect.example.test'],
        keyUsage: [KeyUsage::DIGITAL_SIGNATURE],
        extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
    );
    $dn = ['commonName' => 'inspect.example.test'];
    $csr = new CsrBuilder()->build($dn, $pair['private'], options: $options);
    $certificate = new CertificateBuilder()->selfSign($dn, $pair['private'], options: $options);

    $csrInfo = new CsrInspector()->inspect($csr);
    $certificateInfo = new CertificateInspector()->inspect($certificate);

    expect($csrInfo['subject'])->toContain('inspect.example.test')
        ->and($certificateInfo['subject'])->toContain('inspect.example.test')
        ->and($certificateInfo['issuer'])->toContain('inspect.example.test')
        ->and($csrInfo['public_key'])->toBe($certificateInfo['public_key']);
});

it('verifies an explicit root intermediate leaf chain without hidden trust state', function () {
    $rootKey = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $rootOptions = new CertificateOptions(
        days: 365,
        keyUsage: [KeyUsage::KEY_CERT_SIGN, KeyUsage::CRL_SIGN],
        isCa: true,
    );
    $root = new CertificateBuilder()->selfSign(
        ['commonName' => 'Epicrypt Root'],
        $rootKey['private'],
        options: $rootOptions,
    );

    $intermediateKey = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $intermediateOptions = new CertificateOptions(
        days: 180,
        keyUsage: [KeyUsage::KEY_CERT_SIGN, KeyUsage::CRL_SIGN],
        isCa: true,
    );
    $intermediateCsr = new CsrBuilder()->build(
        ['commonName' => 'Epicrypt Intermediate'],
        $intermediateKey['private'],
        options: $intermediateOptions,
    );
    $intermediate = new CertificateAuthority()->signCsr(
        $intermediateCsr,
        $root,
        $rootKey['private'],
        $intermediateOptions,
    );

    $leafKey = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $leafOptions = new CertificateOptions(
        days: 30,
        sanDns: ['leaf.example.test'],
        keyUsage: [KeyUsage::DIGITAL_SIGNATURE, KeyUsage::KEY_ENCIPHERMENT],
        extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
    );
    $leafCsr = new CsrBuilder()->build(
        ['commonName' => 'leaf.example.test'],
        $leafKey['private'],
        options: $leafOptions,
    );
    $leaf = new CertificateAuthority()->signCsr(
        $leafCsr,
        $intermediate,
        $intermediateKey['private'],
        $leafOptions,
    );

    expect(new CertificateChainVerifier()->verify(
        $leaf,
        [$root],
        CertificatePurpose::SSL_SERVER,
        [$intermediate],
    ))->toBeTrue();
});

it('rejects malformed oversized and duplicate PKI inputs before verification', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $certificate = new CertificateBuilder()->selfSign(['commonName' => 'duplicate.example.test'], $pair['private']);
    $csr = new CsrBuilder()->build(['commonName' => 'duplicate.example.test'], $pair['private']);

    expect(fn () => new CertificateInspector()->inspect(str_repeat('x', 1_048_577)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new CsrInspector()->inspect(str_repeat('x', 1_048_577)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new CsrInspector()->inspect(substr_replace($csr, '!', intdiv(strlen($csr), 2), 1)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => new CertificateChainVerifier()->verify(
            $certificate,
            [$certificate, $certificate],
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => new CertificateChainVerifier()->verify(
            $certificate,
            array_fill(0, 33, $certificate),
        ))->toThrow(ConfigurationException::class)
        ->and(fn () => new CertificateChainVerifier()->verify(
            $certificate,
            [$certificate],
            intermediateCertificatesPem: array_fill(0, 17, $certificate),
        ))->toThrow(ConfigurationException::class);
});
