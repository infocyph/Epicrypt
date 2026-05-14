<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Crypto\AeadCipher;
use Infocyph\Epicrypt\Crypto\Mac;
use Infocyph\Epicrypt\Crypto\SecretBoxCipher;
use Infocyph\Epicrypt\Crypto\Signature;
use Infocyph\Epicrypt\Generate\KeyMaterial\KeyMaterialGenerator;
use PhpBench\Attributes as Bench;

#[Bench\Revs(100)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
final class CryptoBench
{
    private AeadCipher $aeadCipher;

    private Mac $mac;

    private SecretBoxCipher $secretBoxCipher;

    private Signature $signature;

    /**
     * @var array<string, string>
     */
    private array $state = [];

    public function __construct()
    {
        $this->aeadCipher = new AeadCipher();
        $this->secretBoxCipher = new SecretBoxCipher();
        $this->mac = new Mac();
        $this->signature = new Signature();
    }

    public function setUp(): void
    {
        $keyGenerator = new KeyMaterialGenerator();
        $plaintext = str_repeat('epicrypt-benchmark-payload-', 4);
        $this->state['plaintext'] = $plaintext;

        $this->state['aeadKey'] = $keyGenerator->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $this->state['aeadCiphertext'] = $this->aeadCipher->encrypt($plaintext, $this->state['aeadKey'], ['aad' => 'bench-aad']);

        $this->state['secretBoxKey'] = $keyGenerator->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $this->state['secretBoxCiphertext'] = $this->secretBoxCipher->encrypt($plaintext, $this->state['secretBoxKey']);

        $this->state['macKey'] = $this->mac->generateKey();
        $this->state['macValue'] = $this->mac->generate($plaintext, $this->state['macKey']);

        $keyPair = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
        $this->state['signPrivateKey'] = $keyPair['private'];
        $this->state['signPublicKey'] = $keyPair['public'];
        $this->state['detachedSignature'] = $this->signature->sign($plaintext, $this->state['signPrivateKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchAeadDecrypt(): void
    {
        $this->aeadCipher->decrypt($this->state['aeadCiphertext'], $this->state['aeadKey'], ['aad' => 'bench-aad']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchAeadEncrypt(): void
    {
        $this->aeadCipher->encrypt($this->state['plaintext'], $this->state['aeadKey'], ['aad' => 'bench-aad']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchDetachedSignatureSign(): void
    {
        $this->signature->sign($this->state['plaintext'], $this->state['signPrivateKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchDetachedSignatureVerify(): void
    {
        $this->signature->verify($this->state['plaintext'], $this->state['detachedSignature'], $this->state['signPublicKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchMacGenerate(): void
    {
        $this->mac->generate($this->state['plaintext'], $this->state['macKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchMacVerify(): void
    {
        $this->mac->verify($this->state['plaintext'], $this->state['macValue'], $this->state['macKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSecretBoxDecrypt(): void
    {
        $this->secretBoxCipher->decrypt($this->state['secretBoxCiphertext'], $this->state['secretBoxKey']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSecretBoxEncrypt(): void
    {
        $this->secretBoxCipher->encrypt($this->state['plaintext'], $this->state['secretBoxKey']);
    }
}
