<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Certificate\CertificateKeyMatcher;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\Pkcs12;
use Infocyph\Epicrypt\Exception\ConfigurationException;

function pfxFixture(string $commonName = 'pfx.example.test'): array
{
    $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    $certificate = new CertificateBuilder()->selfSign(
        ['commonName' => $commonName],
        $pair['private'],
        days: 30,
    );

    return [$pair, $certificate];
}

it('round trips phpseclib PFX and remains readable by OpenSSL', function () {
    [$pair, $certificate] = pfxFixture();
    $pkcs12 = new Pkcs12();
    $bundle = $pkcs12->export(
        $certificate,
        $pair['private'],
        'pfx-password',
        friendlyName: 'epicrypt-pfx',
        caCertificatesPem: [$certificate],
    );
    $imported = $pkcs12->import($bundle, 'pfx-password');

    expect(new CertificateKeyMatcher()->privateKeyMatches($imported['certificate'], $imported['private_key']))
        ->toBeTrue()
        ->and($imported['ca_certificates'])->toHaveCount(1)
        ->and($imported['friendly_names'])->toContain('epicrypt-pfx');

    $openssl = [];
    expect(openssl_pkcs12_read($bundle, $openssl, 'pfx-password'))->toBeTrue()
        ->and($openssl)->toHaveKeys(['cert', 'pkey']);
});

it('imports OpenSSL generated PKCS12 containers', function () {
    [$pair, $certificate] = pfxFixture('openssl-pfx.example.test');
    $resource = openssl_x509_read($certificate);
    $private = openssl_pkey_get_private($pair['private']);
    expect($resource)->not->toBeFalse()
        ->and($private)->not->toBeFalse();

    $bundle = '';
    expect(openssl_pkcs12_export(
        $resource,
        $bundle,
        $private,
        'interop-password',
        ['friendly_name' => 'openssl-interoperability'],
    ))->toBeTrue();

    $imported = new Pkcs12()->import($bundle, 'interop-password');
    expect(new CertificateKeyMatcher()->privateKeyMatches($imported['certificate'], $imported['private_key']))
        ->toBeTrue();
});

it('rejects wrong passwords mismatched keys and bounded inputs', function () {
    [$pair, $certificate] = pfxFixture();
    [$otherPair] = pfxFixture('other.example.test');
    $pkcs12 = new Pkcs12();
    $bundle = $pkcs12->export($certificate, $pair['private'], 'correct-password');

    expect(fn () => $pkcs12->import($bundle, 'wrong-password'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $pkcs12->export($certificate, $otherPair['private'], 'password'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $pkcs12->import(str_repeat('x', 16_777_217), 'password'))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $pkcs12->export($certificate, $pair['private'], str_repeat('p', 1025)))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $pkcs12->export($certificate, $pair['private'], 'password', friendlyName: "bad\nname"))
        ->toThrow(ConfigurationException::class)
        ->and(fn () => $pkcs12->export(
            $certificate,
            $pair['private'],
            'password',
            caCertificatesPem: array_fill(0, 64, $certificate),
        ))->toThrow(ConfigurationException::class);
});
