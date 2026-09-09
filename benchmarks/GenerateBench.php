<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\NonceGenerator;
use Infocyph\Epicrypt\Generate\RandomBytesGenerator;
use Infocyph\Epicrypt\Generate\SaltGenerator;
use PhpBench\Attributes as Bench;

#[Bench\Revs(200)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
final class GenerateBench
{
    private KeyMaterialGenerator $keyMaterial;

    private NonceGenerator $nonce;

    private RandomBytesGenerator $random;

    private SaltGenerator $salt;

    public function __construct()
    {
        $services = [
            'random' => new RandomBytesGenerator(),
            'nonce' => new NonceGenerator(),
            'salt' => new SaltGenerator(),
            'keyMaterial' => new KeyMaterialGenerator(),
        ];

        $this->random = $services['random'];
        $this->nonce = $services['nonce'];
        $this->salt = $services['salt'];
        $this->keyMaterial = $services['keyMaterial'];
    }

    public function benchKeyMaterialGenerate(): void
    {
        $this->keyMaterial->generate(32);
    }

    public function benchNonceGenerate(): void
    {
        $this->nonce->generate();
    }

    public function benchRandomBytes32(): void
    {
        $this->random->bytes(32);
    }

    public function benchRandomString40(): void
    {
        $this->random->string(40);
    }

    public function benchSaltGenerate(): void
    {
        $this->salt->generate();
    }
}
