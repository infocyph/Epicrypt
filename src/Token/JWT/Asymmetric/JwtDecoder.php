<?php

namespace Infocyph\Epicrypt\Token\JWT\Asymmetric;

use ArrayAccess;
use Infocyph\Epicrypt\Contract\TokenDecoderInterface;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Token\JWT\Key\KeyResolver;
use Infocyph\Epicrypt\Token\JWT\Support\AlgorithmMap;
use Infocyph\Epicrypt\Token\JWT\Support\JwtToken;
use Infocyph\Epicrypt\Token\JWT\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;
use Throwable;

final readonly class JwtDecoder implements TokenDecoderInterface
{
    public function __construct(
        private RegisteredClaims $expectedClaims,
        ?string $passphrase = null,
        private string $algorithm = 'RS512',
    ) {}

    /**
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     */
    public function decode(string $token, mixed $key): object
    {
        if (! is_string($key) && ! is_array($key) && ! ($key instanceof ArrayAccess)) {
            throw new TokenException('Key must be a string or key-set.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $payload] = JwtToken::parse($token);

            if (! isset($header['alg']) || ! is_string($header['alg']) || ! hash_equals(strtoupper($this->algorithm), strtoupper($header['alg']))) {
                throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
            }

            $algorithm = strtoupper($header['alg']);
            $publicKey = KeyResolver::resolve($key, $header['kid'] ?? null);
            $resource = openssl_pkey_get_public($publicKey);

            if ($resource === false) {
                throw new InvalidTokenException('Unable to load public key.');
            }

            $ecdsaLength = AlgorithmMap::ecdsaSignatureLength($algorithm);
            if ($ecdsaLength !== null) {
                $signature = new EcdsaSignatureConverter()->toAsn1($signature, $ecdsaLength);
            }

            $result = openssl_verify(
                $encodedHeader . '.' . $encodedPayload,
                $signature,
                $resource,
                AlgorithmMap::openssl($algorithm),
            );

            if ($result !== 1) {
                throw new InvalidTokenException('Signature verification failed.');
            }

            new JwtValidator($this->expectedClaims)->validate($payload);

            return (object) $payload;
        } catch (UnsupportedAlgorithmException|KeyResolutionException|InvalidTokenException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidTokenException($e->getMessage(), 0, $e);
        }
    }
}
