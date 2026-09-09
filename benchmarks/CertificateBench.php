<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\CertificateInspector;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\CertificateBuilder;
use Infocyph\Epicrypt\Certificate\Pkcs12;
use PhpBench\Attributes as Bench;

#[Bench\Revs(5)]
#[Bench\Iterations(3)]
#[Bench\Warmup(1)]
final class CertificateBench
{
    /** @var array{private: string, public: string} */
    private array $alice;

    /** @var array{private: string, public: string} */
    private array $bob;

    private string $certificate;

    private KeyExchange $exchange;

    private Pkcs12 $pkcs12;

    private string $pfx;

    public function setUp(): void
    {
        $this->exchange = KeyExchange::sodium();
        $this->alice = KeyPairGenerator::sodium()->generate(asBase64Url: true);
        $this->bob = KeyPairGenerator::sodium()->generate(asBase64Url: true);
    }

    public function setUpPki(): void
    {
        $pair = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
        $this->certificate = new CertificateBuilder()->selfSign(
            ['commonName' => 'benchmark.example.test'],
            $pair['private'],
            days: 30,
        );
        $this->pkcs12 = new Pkcs12();
        $this->pfx = $this->pkcs12->export($this->certificate, $pair['private'], 'benchmark-password');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchHkdfKeyExchange(): void
    {
        $this->exchange->deriveKey($this->alice['private'], $this->bob['public'], 32, 'benchmark:v1');
    }

    public function benchOpenSslKeyGeneration(): void
    {
        KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
    }

    #[Bench\BeforeMethods('setUpPki')]
    public function benchOpenSslCertificateParse(): void
    {
        openssl_x509_parse($this->certificate, false);
    }

    #[Bench\BeforeMethods('setUpPki')]
    public function benchPhpseclibCertificateInspect(): void
    {
        new CertificateInspector()->inspect($this->certificate);
    }

    #[Bench\BeforeMethods('setUpPki')]
    public function benchPhpseclibPfxImport(): void
    {
        $this->pkcs12->import($this->pfx, 'benchmark-password');
    }
}
