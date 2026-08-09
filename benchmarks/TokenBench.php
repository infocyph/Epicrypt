<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Certificate\Enum\OpenSslCurveName;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslKeyType;
use Infocyph\Epicrypt\Certificate\Enum\OpenSslRsaBits;
use Infocyph\Epicrypt\Certificate\KeyPairGenerator;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Security\KeyRingEntry;
use Infocyph\Epicrypt\Security\KeyStatus;
use Infocyph\Epicrypt\Token\Jwt\AsymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Jwks;
use Infocyph\Epicrypt\Token\Jwt\JwtClaims;
use Infocyph\Epicrypt\Token\Jwt\JwtPolicy;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use PhpBench\Attributes as Bench;

#[Bench\Revs(100)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
final class TokenBench
{
    /** @var array<string, AsymmetricJwt> */
    private array $asymmetricIssuers = [];

    /** @var array<string, string> */
    private array $asymmetricTokens = [];

    /** @var array<string, AsymmetricJwt> */
    private array $asymmetricVerifiers = [];

    private JwtClaims $claims;

    private Jwks $jwks;

    /** @var array<string, mixed> */
    private array $jwkSet;

    private KeyRing $ring;

    private SymmetricJwt $ringVerifier;

    /** @var array<string, SymmetricJwt> */
    private array $symmetricIssuers = [];

    /** @var array<string, string> */
    private array $symmetricTokens = [];

    /** @var array<string, SymmetricJwt> */
    private array $symmetricVerifiers = [];

    public function setUp(): void
    {
        $this->claims = JwtClaims::issue('benchmark', 'user', ['api'], 600);
        $policy = JwtPolicy::accessToken('benchmark', 'api');
        foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
            $key = SymmetricJwt::generateBinaryKey($algorithm);
            $this->symmetricIssuers[$algorithm->value] = SymmetricJwt::issuer(
                $key,
                'at+jwt',
                algorithm: $algorithm,
            );
            $this->symmetricVerifiers[$algorithm->value] = SymmetricJwt::verifier($key, $policy, $algorithm);
            $this->symmetricTokens[$algorithm->value] = $this->symmetricIssuers[$algorithm->value]->issue($this->claims);
        }

        $rsa = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
        foreach ([
            AsymmetricJwtAlgorithm::RS256,
            AsymmetricJwtAlgorithm::RS384,
            AsymmetricJwtAlgorithm::RS512,
            AsymmetricJwtAlgorithm::PS256,
            AsymmetricJwtAlgorithm::PS384,
            AsymmetricJwtAlgorithm::PS512,
        ] as $algorithm) {
            $this->prepareAsymmetric($algorithm, $rsa, $policy);
        }
        $curves = [
            AsymmetricJwtAlgorithm::ES256->value => OpenSslCurveName::PRIME256V1,
            AsymmetricJwtAlgorithm::ES384->value => OpenSslCurveName::SECP384R1,
            AsymmetricJwtAlgorithm::ES512->value => OpenSslCurveName::SECP521R1,
        ];
        foreach ($curves as $algorithmValue => $curve) {
            $pair = KeyPairGenerator::openSsl(
                OpenSslRsaBits::BITS_3072,
                OpenSslKeyType::EC,
                $curve,
            )->generate();
            $this->prepareAsymmetric(AsymmetricJwtAlgorithm::from($algorithmValue), $pair, $policy);
        }
        $this->prepareAsymmetric(
            AsymmetricJwtAlgorithm::EDDSA,
            KeyPairGenerator::sodiumSign()->generate(),
            $policy,
        );

        $key = SymmetricJwt::generateBinaryKey();
        $this->ring = new KeyRing([
            new KeyRingEntry('active', $key, KeyStatus::ACTIVE, KeyPurpose::JWT_SIGNING, 'HS512', issuer: 'benchmark'),
        ]);
        $this->ringVerifier = SymmetricJwt::verifier(
            $this->ring,
            JwtPolicy::accessToken('benchmark', 'api'),
        );
        $pair = KeyPairGenerator::openSsl(OpenSslRsaBits::BITS_2048)->generate();
        $this->jwks = new Jwks();
        $this->jwkSet = ['keys' => [
            $this->jwks->exportPublicKeyToJwk($pair['public'], 'rsa', AsymmetricJwtAlgorithm::RS256),
        ]];
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function asymmetricAlgorithms(): iterable
    {
        foreach (AsymmetricJwtAlgorithm::cases() as $algorithm) {
            yield $algorithm->value => ['algorithm' => $algorithm->value];
        }
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('asymmetricAlgorithms')]
    public function benchAsymmetricJwtIssue(array $params): void
    {
        $this->asymmetricIssuers[$params['algorithm']]->issue($this->claims);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('asymmetricAlgorithms')]
    public function benchAsymmetricJwtVerify(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->asymmetricVerifiers[$algorithm]->verify($this->asymmetricTokens[$algorithm]);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchJwksVerificationResolution(): void
    {
        $this->jwks->resolvePublicKeyByKid($this->jwkSet, 'rsa', AsymmetricJwtAlgorithm::RS256);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchKeyRingResolution(): void
    {
        $this->ring->resolveForVerification('active', KeyPurpose::JWT_SIGNING, 'HS512', 'benchmark');
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('symmetricAlgorithms')]
    public function benchSymmetricJwtIssue(array $params): void
    {
        $this->symmetricIssuers[$params['algorithm']]->issue($this->claims);
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('symmetricAlgorithms')]
    public function benchSymmetricJwtVerify(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->symmetricVerifiers[$algorithm]->verify($this->symmetricTokens[$algorithm]);
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function symmetricAlgorithms(): iterable
    {
        foreach (SymmetricJwtAlgorithm::cases() as $algorithm) {
            yield $algorithm->value => ['algorithm' => $algorithm->value];
        }
    }

    /**
     * @param array{private: string, public: string} $pair
     */
    private function prepareAsymmetric(
        AsymmetricJwtAlgorithm $algorithm,
        array $pair,
        JwtPolicy $policy,
    ): void {
        $this->asymmetricIssuers[$algorithm->value] = AsymmetricJwt::issuer(
            $pair['private'],
            'at+jwt',
            algorithm: $algorithm,
        );
        $this->asymmetricVerifiers[$algorithm->value] = AsymmetricJwt::verifier(
            $pair['public'],
            $policy,
            $algorithm,
        );
        $this->asymmetricTokens[$algorithm->value] = $this->asymmetricIssuers[$algorithm->value]->issue($this->claims);
    }
}
