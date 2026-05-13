<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\AbstractJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\ExpectedJwtClaims;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidationOptions;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

final readonly class SymmetricJwt extends AbstractJwt
{
    public function __construct(
        private SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512,
        RegisteredClaims|ExpectedJwtClaims|null $expectedClaims = null,
        ?JwtValidationOptions $validationOptions = null,
        ?ClockInterface $clock = null,
    ) {
        parent::__construct('symmetric', $expectedClaims, $validationOptions ?? new JwtValidationOptions(), $clock ?? new SystemClock());
    }

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN, RegisteredClaims|ExpectedJwtClaims|null $expectedClaims = null, ?JwtValidationOptions $validationOptions = null, ?ClockInterface $clock = null): self
    {
        return new self($profile->defaultSymmetricJwtAlgorithm(), $expectedClaims, $validationOptions, $clock);
    }

    protected function algorithmHeaderValue(mixed $algorithm): string
    {
        if (!$algorithm instanceof SymmetricJwtAlgorithm) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        return $algorithm->value;
    }

    protected function configuredAlgorithm(): SymmetricJwtAlgorithm
    {
        return $this->algorithm;
    }

    protected function parseAlgorithmFromHeader(string $algorithm): SymmetricJwtAlgorithm
    {
        return SymmetricJwtAlgorithm::fromHeader($algorithm);
    }

    protected function sign(string $input, string $resolvedKey): string
    {
        return hash_hmac(
            $this->algorithm->hmacAlgorithm(),
            $input,
            $resolvedKey,
            true,
        );
    }

    protected function verifySignature(string $input, string $signature, string $resolvedKey, mixed $algorithm): bool
    {
        if (!$algorithm instanceof SymmetricJwtAlgorithm) {
            throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
        }

        $expected = hash_hmac(
            $algorithm->hmacAlgorithm(),
            $input,
            $resolvedKey,
            true,
        );

        return hash_equals($expected, $signature);
    }
}
