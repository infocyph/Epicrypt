<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\AbstractJwt;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;

final readonly class AsymmetricJwt extends AbstractJwt
{
    public function __construct(
        private ?string $passphrase = null,
        private AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::RS512,
        ?RegisteredClaims $expectedClaims = null,
    ) {
        parent::__construct('asymmetric', $expectedClaims);
    }

    public static function forProfile(SecurityProfile $profile = SecurityProfile::MODERN, ?RegisteredClaims $expectedClaims = null, ?string $passphrase = null): self
    {
        return new self($passphrase, $profile->defaultAsymmetricJwtAlgorithm(), $expectedClaims);
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
            $signature = new EcdsaSignatureConverter()->fromAsn1($signature, $ecdsaLength);
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
            $signature = new EcdsaSignatureConverter()->toAsn1($signature, $ecdsaLength);
        }

        return openssl_verify(
            $input,
            $signature,
            $resource,
            $algorithm->opensslAlgorithm(),
        ) === 1;
    }
}
