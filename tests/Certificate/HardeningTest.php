<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\CertificateOptions;
use Infocyph\Epicrypt\Certificate\CertificateChainVerifier;
use Infocyph\Epicrypt\Certificate\CertificateExpiry;
use Infocyph\Epicrypt\Certificate\CertificateFingerprint;
use Infocyph\Epicrypt\Certificate\Enum\CertificateDigest;
use Infocyph\Epicrypt\Certificate\Enum\CertificatePurpose;
use Infocyph\Epicrypt\Certificate\Enum\ExtendedKeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\KeyUsage;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateParser;
use Infocyph\Epicrypt\Certificate\OpenSSL\CsrBuilder;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Psr\Clock\ClockInterface;

function certificateTestClock(int $timestamp): ClockInterface
{
    return new class($timestamp) implements ClockInterface {
        public function __construct(private readonly int $timestamp) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@'.$this->timestamp);
        }
    };
}

function certificatePemDer(string $pem): string
{
    $encoded = preg_replace('/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/', '', $pem);
    if (!is_string($encoded)) {
        throw new RuntimeException('Unable to normalize test PEM.');
    }
    $der = base64_decode($encoded, true);
    if (!is_string($der)) {
        throw new RuntimeException('Unable to decode test PEM.');
    }

    return $der;
}

it('builds hardened certificates and HKDF-derived session keys', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
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
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();

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
        ->and(fn() => new \Infocyph\Epicrypt\Certificate\OpenSSL\KeyPairGenerator(
            OpenSslRsaBits::BITS_2048,
            OpenSslCurveName::PRIME256V1,
        ))->toThrow(ConfigurationException::class)
        ->and(fn() => KeyPairGenerator::sodium()->generate('unsupported'))
        ->toThrow(ConfigurationException::class)
        ->and(fn() => KeyExchange::sodium()->deriveKey('x', 'y', 32, ''))
        ->toThrow(ConfigurationException::class);
});

it('keeps encoded and binary key exchange APIs equivalent for Sodium and OpenSSL', function () {
    $sodiumEncodedAlice = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $sodiumEncodedBob = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    $sodium = KeyExchange::sodium();
    $encoded = $sodium->deriveKey($sodiumEncodedAlice['private'], $sodiumEncodedBob['public'], 32, 'exchange/v1');
    $binaryOutput = $sodium->deriveBinaryKey($sodiumEncodedAlice['private'], $sodiumEncodedBob['public'], 32, 'exchange/v1');
    expect(sodium_base642bin($encoded, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))->toBe($binaryOutput);

    $sodiumBinaryAlice = KeyPairGenerator::sodium()->generate();
    $sodiumBinaryBob = KeyPairGenerator::sodium()->generate();
    $encodedFromBinary = $sodium->deriveKeyFromBinaryKeys(
        $sodiumBinaryAlice['private'],
        $sodiumBinaryBob['public'],
        32,
        'exchange/v1',
    );
    $binaryFromBinary = $sodium->deriveBinaryKeyFromBinaryKeys(
        $sodiumBinaryAlice['private'],
        $sodiumBinaryBob['public'],
        32,
        'exchange/v1',
    );
    expect(sodium_base642bin($encodedFromBinary, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING))->toBe($binaryFromBinary);

    $alice = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
    $bob = KeyPairGenerator::ec(OpenSslCurveName::PRIME256V1)->generate();
    $openssl = KeyExchange::openSsl();
    $pemDerived = $openssl->deriveBinaryKey($alice['private'], $bob['public'], 32, 'exchange/v1');
    $derDerived = $openssl->deriveBinaryKeyFromBinaryKeys(
        certificatePemDer($alice['private']),
        certificatePemDer($bob['public']),
        32,
        'exchange/v1',
    );
    expect($derDerived)->toBe($pemDerived);
});

it('uses typed certificate purpose digest and deterministic expiry time', function () {
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $certificate = new CertificateBuilder()->selfSign(
        ['commonName' => 'api.example.test'],
        $pair['private'],
        options: new CertificateOptions(
            days: 1,
            sanDns: ['api.example.test'],
            extendedKeyUsage: [ExtendedKeyUsage::SERVER_AUTH],
        ),
    );
    $expiry = new CertificateExpiry(certificateTestClock(time()));
    $expiresAt = $expiry->expiresAt($certificate);

    expect($expiry->isExpired($certificate))->toBeFalse()
        ->and(new CertificateExpiry(certificateTestClock($expiresAt))->isExpired($certificate))->toBeTrue()
        ->and(strlen(new CertificateFingerprint()->fingerprint($certificate, CertificateDigest::SHA256)))->toBe(64)
        ->and(strlen(new CertificateFingerprint()->fingerprint($certificate, CertificateDigest::SHA512)))->toBe(128)
        ->and(is_bool(new CertificateChainVerifier()->verify(
            $certificate,
            [$certificate],
            CertificatePurpose::SSL_SERVER,
        )))->toBeTrue()
        ->and(fn () => $expiry->isExpired($certificate, -1))->toThrow(ConfigurationException::class);
});
