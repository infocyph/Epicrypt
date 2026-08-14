<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\JweKeyManagementAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwe;
use Infocyph\Epicrypt\Token\Jwt\Jws;
use PhpBench\Attributes as Bench;

#[Bench\Revs(20)]
#[Bench\Iterations(3)]
#[Bench\Warmup(1)]
final class JoseBench
{
    /** @var array<string, Jwe> */
    private array $jweDecryptors = [];

    /** @var array<string, Jwe> */
    private array $jweEncryptors = [];

    /** @var array<string, string> */
    private array $jweTokens = [];

    /** @var array<string, Jws> */
    private array $jwsSigners = [];

    /** @var array<string, string> */
    private array $jwsTokens = [];

    /** @var array<string, Jws> */
    private array $jwsVerifiers = [];

    public function setUp(): void
    {
        $this->prepareJws();
        $this->prepareJwe();
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('jweAlgorithms')]
    public function benchJweDecrypt(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->jweDecryptors[$algorithm]->decryptCompact($this->jweTokens[$algorithm]);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('jweAlgorithms')]
    public function benchJweEncrypt(array $params): void
    {
        $this->jweEncryptors[$params['algorithm']]->encryptCompact('benchmark JOSE payload');
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('jwsAlgorithms')]
    public function benchJwsSign(array $params): void
    {
        $this->jwsSigners[$params['algorithm']]->signCompact('benchmark JOSE payload');
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('jwsAlgorithms')]
    public function benchJwsVerify(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->jwsVerifiers[$algorithm]->verifyCompact($this->jwsTokens[$algorithm]);
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function jweAlgorithms(): iterable
    {
        foreach (JweKeyManagementAlgorithm::cases() as $algorithm) {
            yield $algorithm->value => ['algorithm' => $algorithm->value];
        }
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function jwsAlgorithms(): iterable
    {
        foreach ([...SymmetricJwtAlgorithm::cases(), ...AsymmetricJwtAlgorithm::cases()] as $algorithm) {
            yield $algorithm->value => ['algorithm' => $algorithm->value];
        }
    }

    private function prepareJwe(): void
    {
        foreach ([JweKeyManagementAlgorithm::DIRECT, JweKeyManagementAlgorithm::A256KW, JweKeyManagementAlgorithm::A256GCMKW] as $algorithm) {
            $key = random_bytes(32);
            $this->prepareJweAlgorithm($algorithm, $key, $key);
        }
        $rsa = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
        $this->prepareJweAlgorithm(JweKeyManagementAlgorithm::RSA_OAEP_256, $rsa['public'], $rsa['private']);
        $x25519 = KeyPairGenerator::sodium()->generate();
        $this->prepareJweAlgorithm(JweKeyManagementAlgorithm::ECDH_ES, $x25519['public'], $x25519['private']);
        $this->prepareJweAlgorithm(JweKeyManagementAlgorithm::ECDH_ES_A256KW, $x25519['public'], $x25519['private']);
    }

    private function prepareJweAlgorithm(JweKeyManagementAlgorithm $algorithm, string $encryptKey, string $decryptKey): void
    {
        $this->jweEncryptors[$algorithm->value] = new Jwe($encryptKey, $algorithm);
        $this->jweDecryptors[$algorithm->value] = new Jwe($decryptKey, $algorithm);
        $this->jweTokens[$algorithm->value] = $this->jweEncryptors[$algorithm->value]
            ->encryptCompact('benchmark JOSE payload');
    }

    private function prepareJws(): void
    {
        foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
            $key = random_bytes(64);
            $this->prepareJwsAlgorithm($algorithm, $key, $key);
        }
        $rsa = KeyPairGenerator::rsa(OpenSslRsaBits::BITS_2048)->generate();
        foreach ([
            AsymmetricJwtAlgorithm::RS256,
            AsymmetricJwtAlgorithm::RS384,
            AsymmetricJwtAlgorithm::RS512,
            AsymmetricJwtAlgorithm::PS256,
            AsymmetricJwtAlgorithm::PS384,
            AsymmetricJwtAlgorithm::PS512,
        ] as $algorithm) {
            $this->prepareJwsAlgorithm($algorithm, $rsa['private'], $rsa['public']);
        }
        foreach ([
            AsymmetricJwtAlgorithm::ES256->value => OpenSslCurveName::PRIME256V1,
            AsymmetricJwtAlgorithm::ES384->value => OpenSslCurveName::SECP384R1,
            AsymmetricJwtAlgorithm::ES512->value => OpenSslCurveName::SECP521R1,
        ] as $algorithm => $curve) {
            $pair = KeyPairGenerator::ec($curve)->generate();
            $this->prepareJwsAlgorithm(AsymmetricJwtAlgorithm::from($algorithm), $pair['private'], $pair['public']);
        }
        $ed25519 = KeyPairGenerator::sodiumSign()->generate();
        $this->prepareJwsAlgorithm(AsymmetricJwtAlgorithm::EDDSA, $ed25519['private'], $ed25519['public']);
    }

    private function prepareJwsAlgorithm(
        SymmetricJwtAlgorithm|AsymmetricJwtAlgorithm $algorithm,
        string $signingKey,
        string $verificationKey,
    ): void {
        $this->jwsSigners[$algorithm->value] = Jws::signer($signingKey, $algorithm);
        $this->jwsVerifiers[$algorithm->value] = Jws::verifier($verificationKey, $algorithm);
        $this->jwsTokens[$algorithm->value] = $this->jwsSigners[$algorithm->value]
            ->signCompact('benchmark JOSE payload');
    }
}
