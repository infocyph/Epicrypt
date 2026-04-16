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

    private string $aeadCiphertext;

    private string $aeadKey;

    private string $detachedSignature;

    private Mac $mac;

    private string $macKey;

    private string $macValue;

    private string $plaintext;

    private SecretBoxCipher $secretBoxCipher;

    private string $secretBoxCiphertext;

    private string $secretBoxKey;

    private Signature $signature;

    private string $signPrivateKey;

    private string $signPublicKey;

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
        $this->plaintext = str_repeat('epicrypt-benchmark-payload-', 4);

        $this->aeadKey = $keyGenerator->generate(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
        $this->aeadCiphertext = $this->aeadCipher->encrypt($this->plaintext, $this->aeadKey, ['aad' => 'bench-aad']);

        $this->secretBoxKey = $keyGenerator->generate(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
        $this->secretBoxCiphertext = $this->secretBoxCipher->encrypt($this->plaintext, $this->secretBoxKey);

        $this->macKey = $this->mac->generateKey();
        $this->macValue = $this->mac->generate($this->plaintext, $this->macKey);

        $keyPair = KeyPairGenerator::sodiumSign()->generate(asBase64Url: true);
        $this->signPrivateKey = $keyPair['private'];
        $this->signPublicKey = $keyPair['public'];
        $this->detachedSignature = $this->signature->sign($this->plaintext, $this->signPrivateKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchAeadDecrypt(): void
    {
        $this->aeadCipher->decrypt($this->aeadCiphertext, $this->aeadKey, ['aad' => 'bench-aad']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchAeadEncrypt(): void
    {
        $this->aeadCipher->encrypt($this->plaintext, $this->aeadKey, ['aad' => 'bench-aad']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchDetachedSignatureSign(): void
    {
        $this->signature->sign($this->plaintext, $this->signPrivateKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchDetachedSignatureVerify(): void
    {
        $this->signature->verify($this->plaintext, $this->detachedSignature, $this->signPublicKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchMacGenerate(): void
    {
        $this->mac->generate($this->plaintext, $this->macKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchMacVerify(): void
    {
        $this->mac->verify($this->plaintext, $this->macValue, $this->macKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSecretBoxDecrypt(): void
    {
        $this->secretBoxCipher->decrypt($this->secretBoxCiphertext, $this->secretBoxKey);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSecretBoxEncrypt(): void
    {
        $this->secretBoxCipher->encrypt($this->plaintext, $this->secretBoxKey);
    }
}
