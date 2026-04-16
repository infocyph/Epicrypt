<?php

use Infocyph\Epicrypt\Certificate\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\CertificateParser;
use Infocyph\Epicrypt\Certificate\CsrBuilder;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('builds and parses self-signed certificates through Certificate domain', function () {
    $keyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

    $dn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'CA',
        'localityName' => 'San Francisco',
        'organizationName' => 'Epicrypt',
        'organizationalUnitName' => 'Security',
        'commonName' => 'epicrypt.local',
        'emailAddress' => 'security@epicrypt.local',
    ];

    $csr = CsrBuilder::openSsl()->build($dn, $keyPair['private']);
    $certificate = CertificateBuilder::openSsl()->selfSign($dn, $keyPair['private'], 365);
    $parsed = CertificateParser::openSsl()->parse($certificate);

    expect($csr)->toContain('BEGIN CERTIFICATE REQUEST');
    expect($certificate)->toContain('BEGIN CERTIFICATE');
    expect($parsed['subject']['CN'] ?? $parsed['subject']['commonName'] ?? null)->toBe('epicrypt.local');
});

it('supports rsa interoperability in Certificate domain', function () {
    $keyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

    $cipher = new RsaCipher();
    $encrypted = $cipher->encrypt('certificate-rsa-check', $keyPair['public']);
    $decrypted = $cipher->decrypt($encrypted, $keyPair['private']);

    expect($decrypted)->toBe('certificate-rsa-check');
});

it('derives the same shared secret from both parties with sodium key exchange', function () {
    $partyA = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $partyB = KeyPairGenerator::sodium()->generate(asBase64Url: true);

    $exchange = KeyExchange::sodium();

    $secretAB = $exchange->derive($partyA['private'], $partyB['public']);
    $secretBA = $exchange->derive($partyB['private'], $partyA['public']);

    expect($secretAB)->toBe($secretBA);
});

it('rejects curve selection for RSA key pair generation', function () {
    expect(fn () => KeyPairGenerator::openSsl(
        bits: OpenSslRsaBits::BITS_2048,
        curveName: OpenSslCurveName::PRIME256V1,
    ))->toThrow(ConfigurationException::class);
});
