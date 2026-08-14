<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
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

    private KeyExchange $exchange;

    public function setUp(): void
    {
        $this->exchange = KeyExchange::sodium();
        $this->alice = KeyPairGenerator::sodium()->generate(asBase64Url: true);
        $this->bob = KeyPairGenerator::sodium()->generate(asBase64Url: true);
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
}
