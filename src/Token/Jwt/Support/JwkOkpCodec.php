<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;

/** @internal Ed25519 and X25519 JWK encoding boundary. */
final class JwkOkpCodec
{
    /** @return array<string, mixed> */
    public function exportPrivate(
        #[\SensitiveParameter]
        string $privateKey,
        string $kid,
        string $algorithm,
        string $curve,
    ): array {
        $privateLength = $curve === 'Ed25519' ? SODIUM_CRYPTO_SIGN_SECRETKEYBYTES : SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
        if (strlen($privateKey) !== $privateLength) {
            throw new KeyResolutionException('OKP private key has an invalid size.');
        }
        $publicKey = $curve === 'Ed25519'
            ? sodium_crypto_sign_publickey_from_secretkey($privateKey)
            : sodium_crypto_scalarmult_base($privateKey);
        $jwk = $this->exportPublic($publicKey, $kid, $algorithm, $curve);
        $jwk['key_ops'] = [$curve === 'Ed25519' ? 'sign' : 'deriveBits'];
        $jwk['d'] = Base64Url::encode(
            $curve === 'Ed25519' ? substr($privateKey, 0, SODIUM_CRYPTO_SIGN_SEEDBYTES) : $privateKey,
        );

        return $jwk;
    }

    /** @return array<string, mixed> */
    public function exportPublic(string $publicKey, string $kid, string $algorithm, string $curve): array
    {
        $this->assertKey($publicKey, $algorithm, $curve);

        $jwk = [
            'kty' => 'OKP',
            'kid' => $kid,
            'alg' => $algorithm,
            'use' => $curve === 'Ed25519' ? 'sig' : 'enc',
            'crv' => $curve,
            'x' => Base64Url::encode($publicKey),
        ];
        if ($curve === 'Ed25519') {
            $jwk['key_ops'] = ['verify'];
        }

        return $jwk;
    }

    /** @param array<string, mixed> $jwk */
    public function importPrivate(
        #[\SensitiveParameter]
        array $jwk,
        string $algorithm,
        string $curve,
    ): string {
        $operation = $curve === 'Ed25519' ? 'sign' : 'deriveBits';
        if (($jwk['key_ops'] ?? null) !== [$operation] || !is_string($jwk['d'] ?? null)) {
            throw new KeyResolutionException('Private OKP JWK requires the exact private operation and d parameter.');
        }
        $publicJwk = $jwk;
        if ($curve === 'Ed25519') {
            $publicJwk['key_ops'] = ['verify'];
        } else {
            unset($publicJwk['key_ops']);
        }
        $public = $this->importPublic($publicJwk, $algorithm, $curve);

        try {
            $private = Base64Url::decode($jwk['d']);
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('OKP JWK d is not valid Base64URL.', 0, $exception);
        }
        if ($curve === 'Ed25519' && strlen($private) === SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            $private = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($private));
        }
        $privateLength = $curve === 'Ed25519' ? SODIUM_CRYPTO_SIGN_SECRETKEYBYTES : SODIUM_CRYPTO_BOX_SECRETKEYBYTES;
        $derived = strlen($private) === $privateLength
            ? ($curve === 'Ed25519' ? sodium_crypto_sign_publickey_from_secretkey($private) : sodium_crypto_scalarmult_base($private))
            : '';
        if (!hash_equals($public, $derived)) {
            throw new KeyResolutionException('OKP JWK private key does not match its public key.');
        }

        return $private;
    }

    /** @param array<string, mixed> $jwk */
    public function importPublic(array $jwk, string $algorithm, string $curve): string
    {
        if (($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== $curve
            || (isset($jwk['alg']) && $jwk['alg'] !== $algorithm)) {
            throw new KeyResolutionException('OKP JWK metadata does not match the intended algorithm and curve.');
        }
        $use = $curve === 'Ed25519' ? 'sig' : 'enc';
        $validKeyOperations = $curve === 'Ed25519' ? [['verify']] : [[]];
        if ((isset($jwk['use']) && $jwk['use'] !== $use)
            || (isset($jwk['key_ops']) && !in_array($jwk['key_ops'], $validKeyOperations, true))
            || !is_string($jwk['x'] ?? null)) {
            throw new KeyResolutionException('OKP JWK metadata is incompatible with the requested operation.');
        }

        try {
            $publicKey = Base64Url::decode($jwk['x']);
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('OKP JWK x is not valid Base64URL.', 0, $exception);
        }
        $this->assertKey($publicKey, $algorithm, $curve);

        return $publicKey;
    }

    private function assertKey(string $publicKey, string $algorithm, string $curve): void
    {
        $validPair = ($curve === 'Ed25519' && $algorithm === 'EdDSA')
            || ($curve === 'X25519' && str_starts_with($algorithm, 'ECDH-ES'));
        if (!$validPair || strlen($publicKey) !== 32) {
            throw new KeyResolutionException('OKP key must use an approved algorithm/curve pair and contain exactly 32 bytes.');
        }
    }
}
