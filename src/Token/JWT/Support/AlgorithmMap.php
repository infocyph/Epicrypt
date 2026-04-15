<?php

namespace Infocyph\Epicrypt\Token\JWT\Support;

use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;

final class AlgorithmMap
{
    /**
     * @var array<string, int>
     */
    private const array ECDSA_SIGNATURE_LENGTHS = [
        'ES256' => 64,
        'ES384' => 96,
        'ES512' => 132,
    ];
    /**
     * @var array<string, string>
     */
    private const array HMAC = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * @var array<string, int>
     */
    private const array OPENSSL = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
        'ES256' => OPENSSL_ALGO_SHA256,
        'ES384' => OPENSSL_ALGO_SHA384,
        'ES512' => OPENSSL_ALGO_SHA512,
    ];

    public static function ecdsaSignatureLength(string $algorithm): ?int
    {
        $algorithm = strtoupper($algorithm);

        return self::ECDSA_SIGNATURE_LENGTHS[$algorithm] ?? null;
    }

    public static function hmac(string $algorithm): string
    {
        $algorithm = strtoupper($algorithm);

        if (! isset(self::HMAC[$algorithm])) {
            throw new UnsupportedAlgorithmException('Unsupported symmetric JWT algorithm: ' . $algorithm);
        }

        return self::HMAC[$algorithm];
    }

    public static function openssl(string $algorithm): int
    {
        $algorithm = strtoupper($algorithm);

        if (! isset(self::OPENSSL[$algorithm])) {
            throw new UnsupportedAlgorithmException('Unsupported asymmetric JWT algorithm: ' . $algorithm);
        }

        return self::OPENSSL[$algorithm];
    }
}
