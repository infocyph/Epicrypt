<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\KeyRing;

final class Jwks
{
    /**
     * @return array{keys: list<array<string, mixed>>}
     */
    public function exportFromKeyRing(KeyRing $keyRing): array
    {
        $keys = [];
        foreach ($keyRing->keys() as $kid => $key) {
            $keys[] = $this->exportPublicKeyToJwk($key, $kid);
        }

        return ['keys' => $keys];
    }

    /**
     * @return array<string, mixed>
     */
    public function exportPublicKeyToJwk(string $publicKeyPem, string $kid): array
    {
        $resource = openssl_pkey_get_public($publicKeyPem);
        if ($resource === false) {
            throw new KeyResolutionException('Unable to load public key for JWK export.');
        }

        $details = openssl_pkey_get_details($resource);
        if (!is_array($details)) {
            throw new KeyResolutionException('Unable to inspect public key for JWK export.');
        }
        $normalizedDetails = $this->stringKeyArray($details);

        return match ($normalizedDetails['type'] ?? null) {
            OPENSSL_KEYTYPE_RSA => $this->exportRsa($normalizedDetails, $kid),
            OPENSSL_KEYTYPE_EC => $this->exportEc($normalizedDetails, $kid),
            default => throw new KeyResolutionException('Unsupported public key type for JWK export.'),
        };
    }

    /**
     * @param array<string, mixed> $jwk
     */
    public function importPublicKeyFromJwk(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        if (!is_string($kty) || $kty === '') {
            throw new KeyResolutionException('JWK key type "kty" is required.');
        }

        return match (strtoupper($kty)) {
            'RSA' => $this->importRsa($jwk),
            'EC' => $this->importEc($jwk),
            default => throw new KeyResolutionException(sprintf('Unsupported JWK key type "%s".', $kty)),
        };
    }

    /**
     * @param array{keys?: mixed} $jwks
     * @return array<string, mixed>
     */
    public function resolveByKid(array $jwks, string $kid): array
    {
        $keys = $jwks['keys'] ?? null;
        if (!is_array($keys)) {
            throw new KeyResolutionException('JWKS must contain a keys array.');
        }

        foreach ($keys as $entry) {
            if (is_array($entry) && isset($entry['kid']) && is_string($entry['kid']) && hash_equals($entry['kid'], $kid)) {
                return $this->stringKeyArray($entry);
            }
        }

        throw new KeyResolutionException(sprintf('No JWK found for kid "%s".', $kid));
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function resolvePublicKeyByKid(array $jwks, string $kid): string
    {
        return $this->importPublicKeyFromJwk($this->resolveByKid($jwks, $kid));
    }

    private function derBitString(string $value): string
    {
        return "\x03" . $this->derLength(strlen($value) + 1) . "\x00" . $value;
    }

    private function derInteger(string $value): string
    {
        $normalized = ltrim($value, "\x00");
        if ($normalized === '') {
            $normalized = "\x00";
        }

        if ((ord($normalized[0]) & 0x80) !== 0) {
            $normalized = "\x00" . $normalized;
        }

        return "\x02" . $this->derLength(strlen($normalized)) . $normalized;
    }

    private function derLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $result = '';
        while ($length > 0) {
            $result = chr($length & 0xFF) . $result;
            $length >>= 8;
        }

        return chr(0x80 | strlen($result)) . $result;
    }

    private function derOid(string $oid): string
    {
        $parts = explode('.', $oid);
        if (count($parts) < 2) {
            throw new KeyResolutionException(sprintf('Invalid OID "%s".', $oid));
        }

        $first = (int) $parts[0];
        $second = (int) $parts[1];
        $encoded = chr(($first * 40) + $second);

        for ($i = 2; $i < count($parts); $i++) {
            $value = (int) $parts[$i];
            if ($value < 0) {
                throw new KeyResolutionException(sprintf('Invalid OID "%s".', $oid));
            }

            $segment = chr($value & 0x7F);
            $value >>= 7;

            while ($value > 0) {
                $segment = chr(($value & 0x7F) | 0x80) . $segment;
                $value >>= 7;
            }

            $encoded .= $segment;
        }

        return "\x06" . $this->derLength(strlen($encoded)) . $encoded;
    }

    private function derSequence(string $value): string
    {
        return "\x30" . $this->derLength(strlen($value)) . $value;
    }

    /**
     * @param array<string, mixed> $details
     * @return array<string, mixed>
     */
    private function exportEc(array $details, string $kid): array
    {
        $ec = $details['ec'] ?? null;
        if (!is_array($ec) || !isset($ec['curve_name'], $ec['x'], $ec['y']) || !is_string($ec['curve_name']) || !is_string($ec['x']) || !is_string($ec['y'])) {
            throw new KeyResolutionException('Unable to export EC key as JWK.');
        }

        $crv = match ($ec['curve_name']) {
            'prime256v1', 'secp256r1' => 'P-256',
            'secp384r1' => 'P-384',
            'secp521r1' => 'P-521',
            default => throw new KeyResolutionException('Unsupported EC curve for JWK export: ' . $ec['curve_name']),
        };

        return [
            'kty' => 'EC',
            'kid' => $kid,
            'alg' => match ($crv) {
                'P-256' => 'ES256',
                'P-384' => 'ES384',
                'P-521' => 'ES512',
            },
            'use' => 'sig',
            'crv' => $crv,
            'x' => Base64Url::encode($ec['x']),
            'y' => Base64Url::encode($ec['y']),
        ];
    }

    /**
     * @param array<string, mixed> $details
     * @return array<string, mixed>
     */
    private function exportRsa(array $details, string $kid): array
    {
        $rsa = $details['rsa'] ?? null;
        if (!is_array($rsa) || !isset($rsa['n'], $rsa['e']) || !is_string($rsa['n']) || !is_string($rsa['e'])) {
            throw new KeyResolutionException('Unable to export RSA key as JWK.');
        }

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => Base64Url::encode($rsa['n']),
            'e' => Base64Url::encode($rsa['e']),
        ];
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private function importEc(array $jwk): string
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

        if (strlen($xBin) !== strlen($yBin)) {
            throw new KeyResolutionException('EC JWK coordinates must have equal size.');
        }

        $point = "\x04" . $xBin . $yBin;
        $curveOid = match ($crv) {
            'P-256' => $this->derOid('1.2.840.10045.3.1.7'),
            'P-384' => $this->derOid('1.3.132.0.34'),
            'P-521' => $this->derOid('1.3.132.0.35'),
            default => throw new KeyResolutionException(sprintf('Unsupported EC curve "%s".', $crv)),
        };

        $algorithmIdentifier = $this->derSequence(
            $this->derOid('1.2.840.10045.2.1') . $curveOid,
        );

        $spki = $this->derSequence(
            $algorithmIdentifier . $this->derBitString($point),
        );

        return $this->pemEncode('PUBLIC KEY', $spki);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private function importRsa(array $jwk): string
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

        $rsaPublicKey = $this->derSequence(
            $this->derInteger($modulus) . $this->derInteger($exponent),
        );

        $algorithmIdentifier = $this->derSequence(
            $this->derOid('1.2.840.113549.1.1.1') . "\x05\x00",
        );

        $spki = $this->derSequence(
            $algorithmIdentifier . $this->derBitString($rsaPublicKey),
        );

        return $this->pemEncode('PUBLIC KEY', $spki);
    }

    private function pemEncode(string $label, string $binary): string
    {
        $body = chunk_split(base64_encode($binary), 64, "\n");

        return sprintf("-----BEGIN %s-----\n%s-----END %s-----\n", $label, $body, $label);
    }

    /**
     * @param array<mixed, mixed> $input
     * @return array<string, mixed>
     */
    private function stringKeyArray(array $input): array
    {
        $normalized = [];
        foreach ($input as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }
}
