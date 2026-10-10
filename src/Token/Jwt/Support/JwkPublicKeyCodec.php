<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use phpseclib4\Math\BigInteger;

/** @internal Stateless DER/SPKI encoder for JWK public-key imports. */
final class JwkPublicKeyCodec
{
    /**
     * @param array<string, mixed> $jwk
     */
    public static function importEc(array $jwk, AsymmetricJwtAlgorithm $algorithm): string
    {
        $x = $jwk['x'] ?? null;
        $y = $jwk['y'] ?? null;
        $crv = $jwk['crv'] ?? null;
        if (!is_string($x) || !is_string($y) || !is_string($crv) || $x === '' || $y === '' || $crv === '') {
            throw new KeyResolutionException('EC JWK must contain non-empty "crv", "x", and "y" values.');
        }

        try {
            $xBin = Base64Url::decode($x);
            $yBin = Base64Url::decode($y);
        } catch (\Throwable $e) {
            throw new KeyResolutionException('Invalid EC JWK coordinate encoding.', 0, $e);
        }

        $expected = match ($algorithm) {
            AsymmetricJwtAlgorithm::ES256 => ['P-256', 32],
            AsymmetricJwtAlgorithm::ES384 => ['P-384', 48],
            AsymmetricJwtAlgorithm::ES512 => ['P-521', 66],
            default => throw new KeyResolutionException('EC JWK requires an EC JWT algorithm.'),
        };
        if ($crv !== $expected[0] || strlen($xBin) !== $expected[1] || strlen($yBin) !== $expected[1]) {
            throw new KeyResolutionException('EC JWK curve or coordinate size does not match the intended algorithm.');
        }

        $point = "\x04" . $xBin . $yBin;
        $curveOid = self::curveOid($algorithm);

        $algorithmIdentifier = self::derSequence(
            self::derOid('1.2.840.10045.2.1') . $curveOid,
        );

        $spki = self::derSequence(
            $algorithmIdentifier . self::derBitString($point),
        );

        return self::validateImportedKey(self::pemEncode('PUBLIC KEY', $spki), OPENSSL_KEYTYPE_EC);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    public static function importRsa(array $jwk, AsymmetricJwtAlgorithm $algorithm): string
    {
        $n = $jwk['n'] ?? null;
        $e = $jwk['e'] ?? null;
        if (!is_string($n) || !is_string($e) || $n === '' || $e === '') {
            throw new KeyResolutionException('RSA JWK must contain non-empty "n" and "e" values.');
        }

        try {
            $modulus = Base64Url::decode($n);
            $exponent = Base64Url::decode($e);
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('Invalid RSA JWK numeric encoding.', 0, $exception);
        }
        if ((!str_starts_with($algorithm->value, 'RS') && !str_starts_with($algorithm->value, 'PS'))
            || self::bitLength($modulus) < 2048
            || $modulus[0] === "\x00"
            || $exponent[0] === "\x00") {
            throw new KeyResolutionException('RSA JWK requires a matching RSA algorithm and a modulus of at least 2048 bits.');
        }
        $publicExponent = new BigInteger($exponent, 256);
        if ($publicExponent->compare(new BigInteger(3)) < 0 || !$publicExponent->isOdd()) {
            throw new KeyResolutionException('RSA JWK exponent must be an odd integer of at least three.');
        }

        $rsaPublicKey = self::derSequence(
            self::derInteger($modulus) . self::derInteger($exponent),
        );

        $algorithmIdentifier = self::derSequence(
            self::derOid('1.2.840.113549.1.1.1') . "\x05\x00",
        );

        $spki = self::derSequence(
            $algorithmIdentifier . self::derBitString($rsaPublicKey),
        );

        return self::validateImportedKey(self::pemEncode('PUBLIC KEY', $spki), OPENSSL_KEYTYPE_RSA);
    }

    private static function bitLength(string $unsignedInteger): int
    {
        $normalized = ltrim($unsignedInteger, "\x00");
        if ($normalized === '') {
            return 0;
        }

        return ((strlen($normalized) - 1) * 8) + strlen(decbin(ord($normalized[0])));
    }

    private static function byte(int $value): string
    {
        if ($value < 0 || $value > 255) {
            throw new KeyResolutionException('Invalid ASN.1 byte value.');
        }

        return chr($value);
    }

    private static function curveOid(AsymmetricJwtAlgorithm $algorithm): string
    {
        return match ($algorithm) {
            AsymmetricJwtAlgorithm::ES256 => self::derOid('1.2.840.10045.3.1.7'),
            AsymmetricJwtAlgorithm::ES384 => self::derOid('1.3.132.0.34'),
            AsymmetricJwtAlgorithm::ES512 => self::derOid('1.3.132.0.35'),
            default => throw new KeyResolutionException('EC JWK requires an EC JWT algorithm.'),
        };
    }

    private static function derBitString(string $value): string
    {
        return "\x03" . self::derLength(strlen($value) + 1) . "\x00" . $value;
    }

    private static function derInteger(string $value): string
    {
        $normalized = ltrim($value, "\x00");
        if ($normalized === '') {
            $normalized = "\x00";
        }

        if ((ord($normalized[0]) & 0x80) !== 0) {
            $normalized = "\x00" . $normalized;
        }

        return "\x02" . self::derLength(strlen($normalized)) . $normalized;
    }

    private static function derLength(int $length): string
    {
        if ($length < 128) {
            return self::byte($length);
        }

        $result = '';
        while ($length > 0) {
            $result = self::byte($length & 0xFF) . $result;
            $length >>= 8;
        }

        return self::byte(0x80 | strlen($result)) . $result;
    }

    private static function derOid(string $oid): string
    {
        $parts = explode('.', $oid);
        if (count($parts) < 2) {
            throw new KeyResolutionException(sprintf('Invalid OID "%s".', $oid));
        }

        $first = (int) $parts[0];
        $second = (int) $parts[1];
        $encoded = self::byte(($first * 40) + $second);

        for ($i = 2; $i < count($parts); $i++) {
            $value = (int) $parts[$i];
            if ($value < 0) {
                throw new KeyResolutionException(sprintf('Invalid OID "%s".', $oid));
            }

            $segment = self::byte($value & 0x7F);
            $value >>= 7;

            while ($value > 0) {
                $segment = self::byte(($value & 0x7F) | 0x80) . $segment;
                $value >>= 7;
            }

            $encoded .= $segment;
        }

        return "\x06" . self::derLength(strlen($encoded)) . $encoded;
    }

    private static function derSequence(string $value): string
    {
        return "\x30" . self::derLength(strlen($value)) . $value;
    }

    private static function pemEncode(string $label, string $binary): string
    {
        $body = chunk_split(base64_encode($binary), 64, "\n");

        return sprintf("-----BEGIN %s-----\n%s-----END %s-----\n", $label, $body, $label);
    }

    private static function validateImportedKey(string $pem, int $expectedType): string
    {
        $key = openssl_pkey_get_public($pem);
        $details = $key === false ? false : openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['type'] ?? null) !== $expectedType) {
            throw new KeyResolutionException('JWK public key material is not a valid point or key.');
        }

        return $pem;
    }
}
