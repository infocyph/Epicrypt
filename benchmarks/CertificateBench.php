<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyExchange;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Certificate\OpenSSL\RsaCipher;
use PhpBench\Attributes as Bench;

#[Bench\Revs(20)]
#[Bench\Iterations(3)]
#[Bench\Warmup(1)]
final class CertificateBench
{
    /**
     * @var array{private: string, public: string}
     */
    private array $openSslKeyPair;

    private RsaCipher $rsa;

    private string $rsaCiphertext;

    /**
     * @var array{private: string, public: string}
     */
    private array $sodiumA;

    /**
     * @var array{private: string, public: string}
     */
    private array $sodiumB;

    private KeyExchange $sodiumExchange;

    public function __construct()
    {
        $this->rsa = new RsaCipher();
        $this->sodiumExchange = KeyExchange::sodium();
    }

    public function setUp(): void
    {
        $this->openSslKeyPair = KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();
        $this->sodiumA = KeyPairGenerator::sodium()->generate(asBase64Url: true);
        $this->sodiumB = KeyPairGenerator::sodium()->generate(asBase64Url: true);

        $this->rsaCiphertext = $this->rsa->encrypt('epicrypt-benchmark-rsa', $this->openSslKeyPair['public']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchOpenSslKeyPairGenerate(): void
    {
        KeyPairGenerator::openSsl(bits: OpenSslRsaBits::BITS_2048)->generate();
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchRsaDecrypt(): void
    {
        $this->rsa->decrypt($this->rsaCiphertext, $this->openSslKeyPair['private']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchRsaEncrypt(): void
    {
        $this->rsa->encrypt('epicrypt-benchmark-rsa', $this->openSslKeyPair['public']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSodiumKeyExchangeDerive(): void
    {
        $this->sodiumExchange->derive($this->sodiumA['private'], $this->sodiumB['public']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSodiumKeyPairGenerate(): void
    {
        KeyPairGenerator::sodium()->generate(asBase64Url: true);
    }
}
