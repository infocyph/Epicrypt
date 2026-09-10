<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Json;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use phpseclib4\Crypt\PublicKeyLoader;

/** @internal Explicit secret-bearing JWK import/export boundary. */
final class JwkPrivateKeyCodec
{
    /** @return array<string, mixed> */
    public function export(
        #[\SensitiveParameter]
        string $privateKeyPem,
        string $kid,
        AsymmetricJwtAlgorithm $algorithm,
        #[\SensitiveParameter]
        string $password,
    ): array {
        try {
            $key = PublicKeyLoader::loadPrivateKey($privateKeyPem, $password);
            $encoded = $key->withPassword()->toString('JWK');
            $jwk = $this->unwrap(Json::decodeToArray($encoded));
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('Unable to export private key as JWK.', 0, $exception);
        }
        $jwk['kid'] = $kid;
        $jwk['alg'] = $algorithm->value;
        $jwk['use'] = 'sig';
        $jwk['key_ops'] = ['sign'];
        $this->validateShape($jwk, $algorithm);

        return $jwk;
    }

    /** @param array<string, mixed> $jwk */
    public function import(
        #[\SensitiveParameter]
        array $jwk,
        AsymmetricJwtAlgorithm $algorithm,
    ): string {
        $this->validateShape($jwk, $algorithm);

        try {
            $pem = PublicKeyLoader::loadPrivateKey(Json::encode($jwk))->toString('PKCS8');
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('JWK private parameters are invalid or inconsistent.', 0, $exception);
        }
        $resource = openssl_pkey_get_private($pem);
        $details = $resource === false ? false : openssl_pkey_get_details($resource);
        if (!is_array($details) || !$this->matchesDetails($details, $algorithm)) {
            throw new KeyResolutionException('JWK private key does not match its declared algorithm.');
        }

        return $pem;
    }

    /** @param array<mixed, mixed> $details */
    private function matchesDetails(array $details, AsymmetricJwtAlgorithm $algorithm): bool
    {
        if (str_starts_with($algorithm->value, 'RS') || str_starts_with($algorithm->value, 'PS')) {
            return ($details['type'] ?? null) === OPENSSL_KEYTYPE_RSA
                && is_int($details['bits'] ?? null) && $details['bits'] >= 2048;
        }
        $ec = $details['ec'] ?? null;
        $curve = is_array($ec) ? ($ec['curve_name'] ?? null) : null;

        return ($details['type'] ?? null) === OPENSSL_KEYTYPE_EC && $curve === match ($algorithm) {
            AsymmetricJwtAlgorithm::ES256 => 'prime256v1',
            AsymmetricJwtAlgorithm::ES384 => 'secp384r1',
            AsymmetricJwtAlgorithm::ES512 => 'secp521r1',
            default => null,
        };
    }

    /**
     * @param array<string, mixed> $container
     * @return array<string, mixed>
     */
    private function unwrap(array $container): array
    {
        $keys = $container['keys'] ?? null;
        if (!is_array($keys) || count($keys) !== 1 || !is_array($keys[0])) {
            throw new KeyResolutionException('Private-key encoder returned an invalid JWK set.');
        }
        $jwk = [];
        foreach ($keys[0] as $name => $value) {
            if (is_string($name)) {
                $jwk[$name] = $value;
            }
        }

        return $jwk;
    }

    /** @param array<string, mixed> $jwk */
    private function validateShape(array $jwk, AsymmetricJwtAlgorithm $algorithm): void
    {
        $isRsa = str_starts_with($algorithm->value, 'RS') || str_starts_with($algorithm->value, 'PS');
        if (($jwk['kty'] ?? null) !== ($isRsa ? 'RSA' : 'EC') || ($jwk['alg'] ?? null) !== $algorithm->value
            || (isset($jwk['use']) && $jwk['use'] !== 'sig') || ($jwk['key_ops'] ?? null) !== ['sign']) {
            throw new KeyResolutionException('Private JWK metadata does not match the signing operation.');
        }
        $required = $isRsa ? ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] : ['crv', 'x', 'y', 'd'];
        foreach ($required as $name) {
            if (!is_string($jwk[$name] ?? null) || $jwk[$name] === '') {
                throw new KeyResolutionException(sprintf('Private JWK requires non-empty %s.', $name));
            }
        }
        if ($isRsa && isset($jwk['oth'])) {
            throw new KeyResolutionException('Multi-prime RSA JWKs are not supported.');
        }
    }
}
