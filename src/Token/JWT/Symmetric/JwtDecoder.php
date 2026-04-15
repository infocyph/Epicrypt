<?php

namespace Infocyph\Epicrypt\Token\JWT\Symmetric;

use ArrayAccess;
use Infocyph\Epicrypt\Contract\TokenDecoderInterface;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
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
        private string $algorithm = 'HS512',
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

            $secret = KeyResolver::resolve($key, $header['kid'] ?? null);
            $expected = hash_hmac(
                AlgorithmMap::hmac($header['alg']),
                $encodedHeader . '.' . $encodedPayload,
                $secret,
                true,
            );

            if (! hash_equals($expected, $signature)) {
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
