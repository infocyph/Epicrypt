<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use Infocyph\Epicrypt\Generate\KeyMaterial\TokenMaterialGenerator;
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

    private TokenMaterialGenerator $tokenMaterial;

    public function __construct()
    {
        $this->random = new RandomBytesGenerator();
        $this->nonce = new NonceGenerator();
        $this->salt = new SaltGenerator();
        $this->keyMaterial = new KeyMaterialGenerator();
        $this->tokenMaterial = new TokenMaterialGenerator();
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

    public function benchTokenMaterialGenerate(): void
    {
        $this->tokenMaterial->generate(48);
    }
}
