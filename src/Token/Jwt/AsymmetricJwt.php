<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\AbstractJwt;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

final readonly class AsymmetricJwt extends AbstractJwt
{
    public function __construct(
        private ?string $passphrase = null,
        private AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::RS512,
        RegisteredClaims|ExpectedJwtClaims|null $expectedClaims = null,
        ?JwtValidationOptions $validationOptions = null,
        ?ClockInterface $clock = null,
        private EcdsaSignatureConverter $ecdsaSignatureConverter = new EcdsaSignatureConverter(),
    ) {
        parent::__construct('asymmetric', $expectedClaims, $validationOptions ?? new JwtValidationOptions(), $clock ?? new SystemClock());
    }

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN, RegisteredClaims|ExpectedJwtClaims|null $expectedClaims = null, ?string $passphrase = null, ?JwtValidationOptions $validationOptions = null, ?ClockInterface $clock = null): self
    {
        return new self($passphrase, $profile->defaultAsymmetricJwtAlgorithm(), $expectedClaims, $validationOptions, $clock, new EcdsaSignatureConverter());
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function decodeFromJwks(string $token, array $jwks): object
    {
        $result = $this->decodeFromJwksResult($token, $jwks);
        if (!$result->verified) {
            throw new InvalidTokenException('JWT verification failed.');
        }

        return (object) $result->claims;
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function decodeFromJwksResult(string $token, array $jwks): JwtVerificationResult
    {
        $kid = $this->tokenKid($token);
        $publicKey = new Jwks()->resolvePublicKeyByKid($jwks, $kid);

        return $this->decodeResult($token, $publicKey);
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function verifyFromJwks(string $token, array $jwks): bool
    {
        return $this->verifyFromJwksResult($token, $jwks)->verified;
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function verifyFromJwksResult(string $token, array $jwks): JwtVerificationResult
    {
        return $this->decodeFromJwksResult($token, $jwks);
    }

    protected function algorithmHeaderValue(mixed $algorithm): string
    {
        if (!$algorithm instanceof AsymmetricJwtAlgorithm) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        return $algorithm->value;
    }

    protected function configuredAlgorithm(): AsymmetricJwtAlgorithm
    {
        return $this->algorithm;
    }

    protected function parseAlgorithmFromHeader(string $algorithm): AsymmetricJwtAlgorithm
    {
        return AsymmetricJwtAlgorithm::fromHeader($algorithm);
    }

    protected function sign(string $input, string $resolvedKey): string
    {
        $resource = openssl_pkey_get_private($resolvedKey, $this->passphrase ?? '');
        if ($resource === false) {
            throw new TokenException('Unable to load private key for JWT signing.');
        }

        $result = openssl_sign($input, $signature, $resource, $this->algorithm->opensslAlgorithm());
        if (!$result || !is_string($signature)) {
            throw new TokenException('JWT signing failed.');
        }

        $ecdsaLength = $this->algorithm->ecdsaSignatureLength();
        if ($ecdsaLength !== null) {
            $signature = $this->ecdsaSignatureConverter->fromAsn1($signature, $ecdsaLength);
        }

        return $signature;
    }

    protected function verifySignature(string $input, string $signature, string $resolvedKey, mixed $algorithm): bool
    {
        if (!$algorithm instanceof AsymmetricJwtAlgorithm) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        $resource = openssl_pkey_get_public($resolvedKey);
        if ($resource === false) {
            throw new InvalidTokenException('Unable to load public key.');
        }

        $ecdsaLength = $algorithm->ecdsaSignatureLength();
        if ($ecdsaLength !== null) {
            $signature = $this->ecdsaSignatureConverter->toAsn1($signature, $ecdsaLength);
        }

        return openssl_verify(
            $input,
            $signature,
            $resource,
            $algorithm->opensslAlgorithm(),
        ) === 1;
    }

    private function tokenKid(string $token): string
    {
        try {
            [, , , $header] = JwtToken::parse($token);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Invalid JWT format.', 0, $e);
        }

        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new InvalidTokenException('JWT kid header is required for JWKS verification.');
        }

        return $kid;
    }
}
