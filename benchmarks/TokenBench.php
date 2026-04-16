<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\SymmetricJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Infocyph\Epicrypt\Token\Opaque\OpaqueToken;
use Infocyph\Epicrypt\Token\Payload\SignedPayload;
use PhpBench\Attributes as Bench;

#[Bench\Revs(100)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
final class TokenBench
{
    /**
     * @var array<string, mixed>
     */
    private array $jwtClaims;

    private string $jwtSecret;

    private string $jwtToken;

    private string $opaqueDigest;

    private OpaqueToken $opaqueToken;

    private string $opaqueValue;

    /**
     * @var array<string, mixed>
     */
    private array $payloadClaims;

    private string $payloadSecret;

    private string $payloadToken;

    private SignedPayload $signedPayload;

    private SymmetricJwt $symmetricJwtDecoder;

    private SymmetricJwt $symmetricJwtEncoder;

    public function __construct()
    {
        $this->signedPayload = new SignedPayload('bench_payload');
        $this->opaqueToken = new OpaqueToken();
    }

    public function setUp(): void
    {
        $now = time();

        $this->jwtClaims = [
            'iss' => 'epicrypt-benchmark',
            'aud' => 'epicrypt-clients',
            'sub' => 'benchmark-user',
            'jti' => 'bench-jti',
            'nbf' => $now,
            'exp' => $now + 3600,
            'scope' => 'bench:read',
        ];
        $this->jwtSecret = 'bench-symmetric-jwt-secret';
        $this->symmetricJwtEncoder = new SymmetricJwt(SymmetricJwtAlgorithm::HS512);
        $this->symmetricJwtDecoder = new SymmetricJwt(
            SymmetricJwtAlgorithm::HS512,
            new RegisteredClaims('epicrypt-benchmark', 'epicrypt-clients', 'benchmark-user', 'bench-jti'),
        );
        $this->jwtToken = $this->symmetricJwtEncoder->encode($this->jwtClaims, $this->jwtSecret);

        $this->payloadClaims = [
            'sub' => 'benchmark-user',
            'purpose' => 'bench_payload',
            'nonce' => bin2hex(random_bytes(16)),
        ];
        $this->payloadSecret = 'bench-signed-payload-secret';
        $this->payloadToken = $this->signedPayload->encode(
            $this->payloadClaims,
            $this->payloadSecret,
            ['exp' => $now + 3600],
        );

        $this->opaqueValue = $this->opaqueToken->issue();
        $this->opaqueDigest = $this->opaqueToken->hash($this->opaqueValue);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchOpaqueIssue(): void
    {
        $this->opaqueToken->issue(48);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchOpaqueVerify(): void
    {
        $this->opaqueToken->verify($this->opaqueValue, $this->opaqueDigest);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSignedPayloadDecode(): void
    {
        $this->signedPayload->decode($this->payloadToken, $this->payloadSecret);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSignedPayloadEncode(): void
    {
        $this->signedPayload->encode($this->payloadClaims, $this->payloadSecret, ['exp' => time() + 3600]);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSymmetricJwtDecode(): void
    {
        $this->symmetricJwtDecoder->decode($this->jwtToken, $this->jwtSecret);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSymmetricJwtEncode(): void
    {
        $this->symmetricJwtEncoder->encode($this->jwtClaims, $this->jwtSecret);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSymmetricJwtVerify(): void
    {
        $this->symmetricJwtDecoder->verify($this->jwtToken, $this->jwtSecret);
    }
}
