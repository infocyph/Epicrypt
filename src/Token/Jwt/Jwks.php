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
