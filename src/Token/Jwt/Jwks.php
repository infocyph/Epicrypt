<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwkCertificateBinding;
use Infocyph\Epicrypt\Token\Jwt\Support\JwkOkpCodec;
use Infocyph\Epicrypt\Token\Jwt\Support\JwkPrivateKeyCodec;
use Infocyph\Epicrypt\Token\Jwt\Support\JwkPublicKeyCodec;
use Infocyph\Epicrypt\Token\Jwt\Support\JwkThumbprint;

final class Jwks
{
    /**
     * @param array<string, mixed> $jwk
     * @param list<string> $certificateChainPem
     * @return array<string, mixed>
     */
    public function bindCertificateChain(array $jwk, array $certificateChainPem): array
    {
        $jwk = new JwkCertificateBinding()->bind($jwk, $certificateChainPem);
        $this->validateCertificateBinding($jwk);

        return $jwk;
    }

    /**
     * @return array{keys: list<array<string, mixed>>}
     */
    public function exportFromKeyRing(
        #[\SensitiveParameter]
        KeyRing $keyRing,
        AsymmetricJwtAlgorithm $algorithm,
        ?string $issuer = null,
    ): array {
        $keys = [];
        foreach ($keyRing->readCandidates(KeyPurpose::JWT_SIGNING, $algorithm->value, $issuer) as $entry) {
            $keys[] = $this->exportPublicKeyToJwk($entry->key, $entry->id, $algorithm);
        }

        return ['keys' => $keys];
    }

    /**
     * @param non-empty-list<AsymmetricJwtAlgorithm> $algorithms
     * @return array{keys: list<array<string, mixed>>}
     */
    public function exportMixedFromKeyRing(
        #[\SensitiveParameter]
        KeyRing $keyRing,
        array $algorithms,
        ?string $issuer = null,
    ): array {
        $keys = [];
        $seen = [];
        foreach ($algorithms as $algorithm) {
            foreach ($this->exportFromKeyRing($keyRing, $algorithm, $issuer)['keys'] as $jwk) {
                $kid = $jwk['kid'];
                if (!is_string($kid) || isset($seen[$kid])) {
                    throw new KeyResolutionException('Mixed JWKS contains a duplicate or invalid kid.');
                }
                $seen[$kid] = true;
                $keys[] = $jwk;
            }
        }

        return ['keys' => $keys];
    }

    /** @return array<string, mixed> */
    public function exportOkpPrivateKey(
        #[\SensitiveParameter]
        string $privateKey,
        string $kid,
        string $algorithm = 'EdDSA',
        string $curve = 'Ed25519',
    ): array {
        $this->assertKeyId($kid);

        return new JwkOkpCodec()->exportPrivate($privateKey, $kid, $algorithm, $curve);
    }

    /** @return array<string, mixed> */
    public function exportOkpPublicKey(
        string $publicKey,
        string $kid,
        string $algorithm = 'EdDSA',
        string $curve = 'Ed25519',
    ): array {
        $this->assertKeyId($kid);

        return new JwkOkpCodec()->exportPublic($publicKey, $kid, $algorithm, $curve);
    }

    /** @return array<string, mixed> */
    public function exportPrivateKeyToJwk(
        #[\SensitiveParameter]
        string $privateKeyPem,
        string $kid,
        AsymmetricJwtAlgorithm $algorithm,
        #[\SensitiveParameter]
        string $password = '',
    ): array {
        $this->assertKeyId($kid);

        return new JwkPrivateKeyCodec()->export($privateKeyPem, $kid, $algorithm, $password);
    }

    /**
     * @return array<string, mixed>
     */
    public function exportPublicKeyToJwk(
        string $publicKeyPem,
        string $kid,
        AsymmetricJwtAlgorithm $algorithm,
    ): array {
        $this->assertKeyId($kid);
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
            OPENSSL_KEYTYPE_RSA => $this->exportRsa($normalizedDetails, $kid, $algorithm),
            OPENSSL_KEYTYPE_EC => $this->exportEc($normalizedDetails, $kid, $algorithm),
            default => throw new KeyResolutionException('Unsupported public key type for JWK export.'),
        };
    }

    /** @return array<string, mixed> */
    public function exportSymmetricSecretJwk(
        #[\SensitiveParameter]
        string $key,
        string $kid,
        string $algorithm,
        string $use = 'sig',
    ): array {
        $this->assertKeyId($kid);
        if (strlen($key) < 32 || !in_array($use, ['sig', 'enc'], true)) {
            throw new KeyResolutionException('Symmetric JWK requires at least 32 bytes and a compatible use.');
        }

        return [
            'kty' => 'oct',
            'kid' => $kid,
            'alg' => $algorithm,
            'use' => $use,
            'key_ops' => [$use === 'sig' ? 'verify' : 'decrypt'],
            'k' => Base64Url::encode($key),
        ];
    }

    /** @param array<string, mixed> $jwk */
    public function importOkpPrivateKey(
        #[\SensitiveParameter]
        array $jwk,
        string $algorithm,
        string $curve,
    ): string {
        return new JwkOkpCodec()->importPrivate($jwk, $algorithm, $curve);
    }

    /** @param array<string, mixed> $jwk */
    public function importOkpPublicKey(array $jwk, string $algorithm, string $curve): string
    {
        return new JwkOkpCodec()->importPublic($jwk, $algorithm, $curve);
    }

    /** @param array<string, mixed> $jwk */
    public function importPrivateKeyFromJwk(
        #[\SensitiveParameter]
        array $jwk,
        AsymmetricJwtAlgorithm $algorithm,
    ): string {
        return new JwkPrivateKeyCodec()->import($jwk, $algorithm);
    }

    /**
     * @param array<string, mixed> $jwk
     */
    public function importPublicKeyFromJwk(array $jwk, AsymmetricJwtAlgorithm $algorithm): string
    {
        $this->validateMetadata($jwk, $algorithm);
        $kty = $jwk['kty'] ?? null;
        if (!is_string($kty) || $kty === '') {
            throw new KeyResolutionException('JWK key type "kty" is required.');
        }

        return match (strtoupper($kty)) {
            'RSA' => JwkPublicKeyCodec::importRsa($jwk, $algorithm),
            'EC' => JwkPublicKeyCodec::importEc($jwk, $algorithm),
            default => throw new KeyResolutionException(sprintf('Unsupported JWK key type "%s".', $kty)),
        };
    }

    /** @param array<string, mixed> $jwk */
    public function importSymmetricKey(#[\SensitiveParameter] array $jwk, string $algorithm, string $use = 'sig'): string
    {
        $operation = $use === 'sig' ? 'verify' : 'decrypt';
        if (($jwk['kty'] ?? null) !== 'oct' || ($jwk['alg'] ?? null) !== $algorithm
            || (isset($jwk['use']) && $jwk['use'] !== $use)
            || (isset($jwk['key_ops']) && $jwk['key_ops'] !== [$operation])) {
            throw new KeyResolutionException('Symmetric JWK metadata is incompatible with the requested operation.');
        }
        $encoded = $jwk['k'] ?? null;
        if (!is_string($encoded)) {
            throw new KeyResolutionException('Symmetric JWK must contain k.');
        }

        try {
            $key = Base64Url::decode($encoded);
        } catch (\Throwable $exception) {
            throw new KeyResolutionException('Symmetric JWK k is not valid Base64URL.', 0, $exception);
        }
        if (strlen($key) < 32) {
            throw new KeyResolutionException('Symmetric JWK key material must contain at least 32 bytes.');
        }

        return $key;
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

        $resolved = null;
        $seen = [];
        foreach ($keys as $entry) {
            if (!is_array($entry) || !isset($entry['kid']) || !is_string($entry['kid'])) {
                throw new KeyResolutionException('Every JWK must contain a string kid.');
            }
            if (isset($seen[$entry['kid']])) {
                throw new KeyResolutionException(sprintf('Duplicate JWK kid "%s".', $entry['kid']));
            }
            $seen[$entry['kid']] = true;
            if (hash_equals($entry['kid'], $kid)) {
                $resolved = $this->stringKeyArray($entry);
            }
        }

        if ($resolved !== null) {
            return $resolved;
        }

        throw new KeyResolutionException(sprintf('No JWK found for kid "%s".', $kid));
    }

    /**
     * @param array<string, mixed> $jwks
     */
    public function resolvePublicKeyByKid(
        array $jwks,
        string $kid,
        AsymmetricJwtAlgorithm $algorithm,
    ): string {
        return $this->importPublicKeyFromJwk($this->resolveByKid($jwks, $kid), $algorithm);
    }

    /** @param array<string, mixed> $jwk */
    public function thumbprint(array $jwk): string
    {
        return new JwkThumbprint()->calculate($jwk);
    }

    /** @param array<string, mixed> $jwk */
    public function thumbprintUri(array $jwk): string
    {
        return new JwkThumbprint()->uri($jwk);
    }

    /** @param array<string, mixed> $jwk */
    public function validateCertificateBinding(array $jwk): void
    {
        $algorithm = $jwk['alg'] ?? null;
        if (!is_string($algorithm) || ($resolved = AsymmetricJwtAlgorithm::tryFrom($algorithm)) === null || $resolved->isEdDsa()) {
            throw new KeyResolutionException('Certificate binding requires a supported RSA or EC JWK algorithm.');
        }
        new JwkCertificateBinding()->validate($jwk, $this->importPublicKeyFromJwk($jwk, $resolved));
    }

    private function assertKeyId(string $kid): void
    {
        if (preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $kid) !== 1) {
            throw new KeyResolutionException('JWK kid must be a Base64URL-safe identifier.');
        }
    }

    /**
     * @param array<string, mixed> $details
     * @return array<string, mixed>
     */
    private function exportEc(array $details, string $kid, AsymmetricJwtAlgorithm $algorithm): array
    {
        $ec = $details['ec'] ?? null;
        if (!is_array($ec)
            || !isset($ec['curve_name'], $ec['x'], $ec['y'])
            || !is_string($ec['curve_name'])
            || !is_string($ec['x'])
            || !is_string($ec['y'])
            || $ec['x'] === ''
            || $ec['y'] === '') {
            throw new KeyResolutionException('Unable to export EC key as JWK.');
        }

        $crv = match ($ec['curve_name']) {
            'prime256v1', 'secp256r1' => 'P-256',
            'secp384r1' => 'P-384',
            'secp521r1' => 'P-521',
            default => throw new KeyResolutionException('Unsupported EC curve for JWK export: ' . $ec['curve_name']),
        };
        $expectedAlgorithm = match ($crv) {
            'P-256' => AsymmetricJwtAlgorithm::ES256,
            'P-384' => AsymmetricJwtAlgorithm::ES384,
            'P-521' => AsymmetricJwtAlgorithm::ES512,
        };
        if ($algorithm !== $expectedAlgorithm) {
            throw new KeyResolutionException('EC key curve does not match the intended JWT algorithm.');
        }

        $coordinateLength = match ($crv) {
            'P-256' => 32,
            'P-384' => 48,
            'P-521' => 66,
        };
        if (strlen($ec['x']) > $coordinateLength || strlen($ec['y']) > $coordinateLength) {
            throw new KeyResolutionException('EC key coordinates exceed the expected curve width.');
        }
        $x = str_pad($ec['x'], $coordinateLength, "\x00", STR_PAD_LEFT);
        $y = str_pad($ec['y'], $coordinateLength, "\x00", STR_PAD_LEFT);

        return [
            'kty' => 'EC',
            'kid' => $kid,
            'alg' => $algorithm->value,
            'use' => 'sig',
            'crv' => $crv,
            'x' => Base64Url::encode($x),
            'y' => Base64Url::encode($y),
        ];
    }

    /**
     * @param array<string, mixed> $details
     * @return array<string, mixed>
     */
    private function exportRsa(array $details, string $kid, AsymmetricJwtAlgorithm $algorithm): array
    {
        $rsa = $details['rsa'] ?? null;
        if (!is_array($rsa) || !isset($rsa['n'], $rsa['e']) || !is_string($rsa['n']) || !is_string($rsa['e'])) {
            throw new KeyResolutionException('Unable to export RSA key as JWK.');
        }

        if ((!str_starts_with($algorithm->value, 'RS') && !str_starts_with($algorithm->value, 'PS'))
            || !is_int($details['bits'] ?? null) || $details['bits'] < 2048) {
            throw new KeyResolutionException('RSA JWK export requires a matching RSA algorithm and at least 2048 bits.');
        }

        return [
            'kty' => 'RSA',
            'kid' => $kid,
            'alg' => $algorithm->value,
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

    /** @param array<string, mixed> $jwk */
    private function validateMetadata(array $jwk, AsymmetricJwtAlgorithm $algorithm): void
    {
        if (($jwk['alg'] ?? null) !== $algorithm->value) {
            throw new KeyResolutionException('JWK alg must exactly match the intended JWT algorithm.');
        }
        if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
            throw new KeyResolutionException('JWK use must be sig when provided.');
        }
        if (isset($jwk['key_ops']) && (!is_array($jwk['key_ops']) || $jwk['key_ops'] !== ['verify'])) {
            throw new KeyResolutionException('Public verification JWK key_ops must be exactly ["verify"] when provided.');
        }

        $expectedType = str_starts_with($algorithm->value, 'RS') || str_starts_with($algorithm->value, 'PS') ? 'RSA' : 'EC';
        if (($jwk['kty'] ?? null) !== $expectedType) {
            throw new KeyResolutionException('JWK kty does not match the intended JWT algorithm.');
        }
    }
}
