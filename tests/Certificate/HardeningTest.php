<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateParser;
use Infocyph\Epicrypt\Certificate\OpenSSL\CsrBuilder;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('builds hardened certificates and HKDF-derived session keys', function () {
    $pair = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
    $options = new CertificateOptions(
        days: 30,
        sanDns: ['api.example.test'],
        sanIp: ['127.0.0.1'],
        sanEmail: ['security@example.test'],
        keyUsage: [KeyUsage::DIGITAL_SIGNATURE],
        extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
    );
    $dn = ['commonName' => 'api.example.test'];
    $csr = new CsrBuilder()->build($dn, $pair['private'], options: $options);
    $certificate = new CertificateBuilder()->selfSign($dn, $pair['private'], options: $options);

    expect($csr)->toContain('BEGIN CERTIFICATE REQUEST')
        ->and(new CertificateParser()->parse($certificate))->toHaveKey('subject');

    $alice = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $bob = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $exchange = KeyExchange::sodium();
    expect($exchange->deriveKey($alice['private'], $bob['public'], 32, 'chat-session:v1'))
        ->toBe($exchange->deriveKey($bob['private'], $alice['public'], 32, 'chat-session:v1'));
});

it('rejects certificate config injection and invalid SAN and lifetime input', function () {
    $pair = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();

    expect(fn() => new CertificateOptions(sanDns: ["good.test\nDNS.2=evil.test"]))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => new CertificateOptions(sanIp: ['999.1.1.1']))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => new CertificateOptions(sanEmail: ['not-an-email']))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => new CertificateOptions(days: 0))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => new CsrBuilder()->build(['commonName' => "safe.test\0evil"], $pair['private']))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => new CertificateOptions(keyUsage: ['digitalSignature']))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => KeyPairGenerator::openSsl(
            OpenSslRsaBits::BITS_2048,
            OpenSslKeyType::RSA,
            OpenSslCurveName::PRIME256V1,
        ))->toThrow(ConfigurationException::class)
        ->and(fn() => KeyExchange::sodium()->deriveKey('x', 'y', 32, ''))
        ->toThrow(ConfigurationException::class);
});
