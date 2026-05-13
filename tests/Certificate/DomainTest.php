<?php

use Infocyph\Epicrypt\Certificate\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\CertificateAuthority;
use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
use Infocyph\Epicrypt\Certificate\CertificateExpiry;
use Infocyph\Epicrypt\Certificate\CertificateFingerprint;
use Infocyph\Epicrypt\Certificate\CertificateKeyMatcher;
use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\CertificateParser;
use Infocyph\Epicrypt\Certificate\CsrBuilder;
use Infocyph\Epicrypt\Certificate\Enum\KeyExchangeBackend;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\PemNormalizer;
use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Crypto\InvalidKeyException;

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

it('builds csr and certificate with SAN options', function () {
    $keyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();
    $options = new CertificateOptions(
        sanDns: ['epicrypt.local', 'api.epicrypt.local'],
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth'],
    );

    $dn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'CA',
        'localityName' => 'San Francisco',
        'organizationName' => 'Epicrypt',
        'organizationalUnitName' => 'Security',
        'commonName' => 'epicrypt.local',
        'emailAddress' => 'security@epicrypt.local',
    ];

    $csr = CsrBuilder::openSsl()->build($dn, $keyPair['private'], options: $options);
    $certificate = CertificateBuilder::openSsl()->selfSign($dn, $keyPair['private'], options: $options);
    $parsed = CertificateParser::openSsl()->parse($certificate);
    $san = $parsed['extensions']['subjectAltName'] ?? null;

    expect($csr)->toContain('BEGIN CERTIFICATE REQUEST');
    expect($san)->toBeString();
    expect((string) $san)->toContain('DNS:epicrypt.local');
    expect((string) $san)->toContain('DNS:api.epicrypt.local');
});

it('supports rsa interoperability in Certificate domain', function () {
    $keyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

    $cipher = new RsaCipher;
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

it('supports enum based key exchange backend selection', function () {
    $exchange = KeyExchange::forBackend(KeyExchangeBackend::SODIUM);

    expect($exchange->backend())->toBe(KeyExchangeBackend::SODIUM);
});

it('rejects invalid sodium key exchange key material', function () {
    $exchange = KeyExchange::sodium();

    expect(fn() => $exchange->derive('short-private', 'short-public'))
        ->toThrow(InvalidKeyException::class);
});

it('signs csr using a certificate authority and validates certificate utilities', function () {
    $caKeyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();
    $leafKeyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();

    $caDn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'CA',
        'localityName' => 'San Francisco',
        'organizationName' => 'Epicrypt CA',
        'organizationalUnitName' => 'Root',
        'commonName' => 'epicrypt-root.local',
        'emailAddress' => 'root@epicrypt.local',
    ];
    $leafDn = [
        'countryName' => 'US',
        'stateOrProvinceName' => 'CA',
        'localityName' => 'San Francisco',
        'organizationName' => 'Epicrypt',
        'organizationalUnitName' => 'Leaf',
        'commonName' => 'service.epicrypt.local',
        'emailAddress' => 'service@epicrypt.local',
    ];

    $caOptions = new CertificateOptions(isCa: true, keyUsage: ['keyCertSign', 'cRLSign'], sanDns: ['epicrypt-root.local']);
    $leafOptions = new CertificateOptions(sanDns: ['service.epicrypt.local'], keyUsage: ['digitalSignature', 'keyEncipherment'], extendedKeyUsage: ['serverAuth']);

    $caCertificate = CertificateBuilder::openSsl()->selfSign($caDn, $caKeyPair['private'], options: $caOptions);
    $leafCsr = CsrBuilder::openSsl()->build($leafDn, $leafKeyPair['private'], options: $leafOptions);
    $leafCertificate = CertificateAuthority::openSsl()->signCsr($leafCsr, $caCertificate, $caKeyPair['private'], $leafOptions);

    $fingerprint = (new CertificateFingerprint())->fingerprint($leafCertificate);
    $expiresAt = (new CertificateExpiry())->expiresAt($leafCertificate);
    $notExpired = (new CertificateExpiry())->isExpired($leafCertificate) === false;
    $matches = (new CertificateKeyMatcher())->privateKeyMatches($leafCertificate, $leafKeyPair['private']);
    $chainValid = (new CertificateChainVerifier())->verify($leafCertificate, [$caCertificate]);
    $normalized = (new PemNormalizer())->normalize($leafCertificate);

    expect($leafCertificate)->toContain('BEGIN CERTIFICATE');
    expect($fingerprint)->toHaveLength(64);
    expect($expiresAt)->toBeGreaterThan(time());
    expect($notExpired)->toBeTrue();
    expect($matches)->toBeTrue();
    expect($chainValid)->toBeTrue();
    expect($normalized)->toContain("-----BEGIN CERTIFICATE-----\n");
});

it('rejects curve selection for RSA key pair generation', function () {
    expect(fn () => KeyPairGenerator::openSsl(
        bits: OpenSslRsaBits::BITS_2048,
        curveName: OpenSslCurveName::PRIME256V1,
    ))->toThrow(ConfigurationException::class);
});
