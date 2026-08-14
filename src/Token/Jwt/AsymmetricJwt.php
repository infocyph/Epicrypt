<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\EcdsaSignatureConverter;
use Infocyph\Epicrypt\Security\KeyPurpose;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use OpenSSLAsymmetricKey;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey as RsaPrivateKey;
use phpseclib3\Crypt\RSA\PublicKey as RsaPublicKey;
use Psr\Clock\ClockInterface;
use Throwable;

final readonly class AsymmetricJwt
{
    private const string ISSUER = 'issuer';

    private const string VERIFIER = 'verifier';

    private function __construct(
        private string $mode,
        #[\SensitiveParameter]
        private string|KeyRing $key,
        private AsymmetricJwtAlgorithm $algorithm,
        private string $type,
        private ?string $keyId,
        private ?JwtPolicy $policy,
        private ?JwtReplayStoreInterface $replayStore,
        #[\SensitiveParameter]
        private ?string $passphrase,
        private ClockInterface $clock,
    ) {
        if ($this->type === '' || strlen($this->type) > 128) {
            throw new ConfigurationException('JWT type must contain between 1 and 128 bytes.');
        }
        if ($this->keyId !== null && preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $this->keyId) !== 1) {
            throw new ConfigurationException('JWT key id must be a Base64URL-safe identifier.');
        }
        if ($this->policy !== null && $this->policy->replayMode !== JwtReplayMode::NONE && $this->replayStore === null) {
            throw new ConfigurationException('A replay store is required by the selected JWT replay policy.');
        }
        if (is_string($this->key)) {
            $this->validateKey($this->key, $this->mode === self::ISSUER);
        }
    }

    public static function issuer(
        #[\SensitiveParameter]
        string $privateKey,
        string $type,
        ?string $keyId = null,
        AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::ES256,
        #[\SensitiveParameter]
        ?string $passphrase = null,
        ClockInterface $clock = new SystemClock(),
    ): self {
        return new self(self::ISSUER, $privateKey, $algorithm, $type, $keyId, null, null, $passphrase, $clock);
    }

    public static function verifier(
        #[\SensitiveParameter]
        string|KeyRing $publicKey,
        JwtPolicy $policy,
        AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::ES256,
        ?JwtReplayStoreInterface $replayStore = null,
        ClockInterface $clock = new SystemClock(),
    ): self {
        return new self(self::VERIFIER, $publicKey, $algorithm, $policy->expectedType, null, $policy, $replayStore, null, $clock);
    }

    public function issue(JwtClaims $claims): string
    {
        if ($this->mode !== self::ISSUER || !is_string($this->key)) {
            throw new ConfigurationException('This JWT instance is not configured for issuance.');
        }

        $header = ['alg' => $this->algorithm->value, 'typ' => $this->type];
        if ($this->keyId !== null) {
            $header['kid'] = $this->keyId;
        }
        [$encodedHeader, $encodedPayload] = JwtToken::encodeSegments($header, $claims->toArray());
        $input = $encodedHeader . '.' . $encodedPayload;
        $signature = $this->sign($input, $this->key);

        $ecdsaLength = $this->algorithm->ecdsaSignatureLength();
        if ($ecdsaLength !== null) {
            $signature = new EcdsaSignatureConverter()->fromAsn1($signature, $ecdsaLength);
        }

        return $input . '.' . Base64Url::encode($signature);
    }

    public function verify(#[\SensitiveParameter] string $token): bool
    {
        return $this->verifyResult($token)->valid;
    }

    public function verifyResult(#[\SensitiveParameter] string $token): JwtVerificationResult
    {
        if ($this->mode !== self::VERIFIER || $this->policy === null) {
            throw new ConfigurationException('This JWT instance is not configured for verification.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $claims] = JwtToken::parse($token);
        } catch (Throwable) {
            return JwtVerificationResult::failure(JwtFailureReason::MALFORMED);
        }

        $headerFailure = $this->validateHeader($header);
        if ($headerFailure !== null) {
            return JwtVerificationResult::failure($headerFailure);
        }
        [$resolvedKey, $matchedKeyId, $keyFailure] = $this->resolveKey($header['kid'] ?? null);
        if ($keyFailure !== null || !is_string($resolvedKey)) {
            return JwtVerificationResult::failure($keyFailure ?? JwtFailureReason::KEY_NOT_USABLE);
        }

        try {
            $ecdsaLength = $this->algorithm->ecdsaSignatureLength();
            if ($ecdsaLength !== null) {
                $signature = new EcdsaSignatureConverter()->toAsn1($signature, $ecdsaLength);
            }
        } catch (Throwable) {
            return JwtVerificationResult::failure(JwtFailureReason::INVALID_SIGNATURE);
        }

        if (!$this->verifySignature($encodedHeader . '.' . $encodedPayload, $signature, $resolvedKey)) {
            return JwtVerificationResult::failure(JwtFailureReason::INVALID_SIGNATURE);
        }

        $validation = JwtValidator::validate($claims, $this->policy, $this->clock->now()->getTimestamp());
        if ($validation instanceof JwtFailureReason) {
            return JwtVerificationResult::failure($validation);
        }
        if (!$this->passesReplayPolicy($validation['issuer'], $validation['jwt_id'], $validation['expires_at'])) {
            return JwtVerificationResult::failure(JwtFailureReason::REPLAYED);
        }

        return JwtVerificationResult::success($claims, $header, $matchedKeyId);
    }

    private function configureRsaPss(
        #[\SensitiveParameter]
        RsaPrivateKey|RsaPublicKey $key,
    ): RsaPrivateKey|RsaPublicKey {
        $configured = $key->withPadding(RSA::SIGNATURE_PSS);
        if (!$configured instanceof RsaPrivateKey && !$configured instanceof RsaPublicKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS padding.');
        }
        $configured = $configured->withHash($this->algorithm->hashAlgorithm());
        if (!$configured instanceof RsaPrivateKey && !$configured instanceof RsaPublicKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS hash.');
        }
        $configured = $configured->withMGFHash($this->algorithm->hashAlgorithm());
        if (!$configured instanceof RsaPrivateKey && !$configured instanceof RsaPublicKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS MGF hash.');
        }
        $configured = $configured->withSaltLength(strlen(hash($this->algorithm->hashAlgorithm(), '', true)));
        if (!$configured instanceof RsaPrivateKey && !$configured instanceof RsaPublicKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS salt length.');
        }

        return $configured;
    }

    /** @return non-empty-string */
    private function edDsaKey(#[\SensitiveParameter] string $key, bool $private): string
    {
        $expected = $private ? SODIUM_CRYPTO_SIGN_SECRETKEYBYTES : SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;
        if (strlen($key) !== $expected) {
            throw new ConfigurationException(sprintf('EdDSA %s keys must contain exactly %d raw bytes.', $private ? 'private' : 'public', $expected));
        }

        return $key;
    }

    private function loadAndValidateKey(#[\SensitiveParameter] string $pem, bool $private): OpenSSLAsymmetricKey
    {
        $key = $private
            ? openssl_pkey_get_private($pem, $this->passphrase ?? '')
            : openssl_pkey_get_public($pem);
        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new ConfigurationException('Unable to load JWT key material.');
        }

        $details = openssl_pkey_get_details($key);
        if (!is_array($details)) {
            throw new ConfigurationException('Unable to inspect JWT key material.');
        }
        $this->validateKeyDetails($details);

        return $key;
    }

    private function passesReplayPolicy(string $issuer, string $jwtId, int $expiresAt): bool
    {
        return match ($this->policy?->replayMode) {
            null, JwtReplayMode::NONE => true,
            JwtReplayMode::DENYLIST => $this->replayStore?->isRevoked($issuer, $jwtId, $expiresAt) === false,
            JwtReplayMode::SINGLE_USE => $this->replayStore?->consume($issuer, $jwtId, $expiresAt) === true,
        };
    }

    /** @return array{?string, ?string, ?JwtFailureReason} */
    private function resolveKey(mixed $keyId): array
    {
        if (is_string($this->key)) {
            return [$this->key, null, null];
        }
        if (!is_string($keyId) || $keyId === '') {
            return [null, null, JwtFailureReason::UNKNOWN_KEY];
        }

        $entry = $this->key->resolveForVerification(
            $keyId,
            KeyPurpose::JWT_SIGNING,
            $this->algorithm->value,
            $this->policy?->expectedIssuer,
        );

        return $entry !== null
            ? [$entry->key, $entry->id, null]
            : [null, null, JwtFailureReason::UNKNOWN_KEY];
    }

    private function rsaPssPrivateKey(#[\SensitiveParameter] string $key): RsaPrivateKey
    {
        $resource = openssl_pkey_get_private($key, $this->passphrase ?? '');
        if (!$resource instanceof OpenSSLAsymmetricKey || !openssl_pkey_export($resource, $normalizedKey) || !is_string($normalizedKey)) {
            throw new ConfigurationException('Unable to normalize RSA-PSS private key material.');
        }
        $loaded = PublicKeyLoader::loadPrivateKey($normalizedKey);
        if (!$loaded instanceof RsaPrivateKey) {
            throw new ConfigurationException('RSA-PSS signing requires an RSA private key.');
        }
        $configured = $this->configureRsaPss($loaded);
        if (!$configured instanceof RsaPrivateKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS private key.');
        }

        return $configured;
    }

    private function rsaPssPublicKey(string $key): RsaPublicKey
    {
        $loaded = PublicKeyLoader::loadPublicKey($key);
        if (!$loaded instanceof RsaPublicKey) {
            throw new ConfigurationException('RSA-PSS verification requires an RSA public key.');
        }
        $configured = $this->configureRsaPss($loaded);
        if (!$configured instanceof RsaPublicKey) {
            throw new ConfigurationException('Unable to configure RSA-PSS public key.');
        }

        return $configured;
    }

    private function sign(#[\SensitiveParameter] string $input, #[\SensitiveParameter] string $privateKey): string
    {
        if ($this->algorithm->isEdDsa()) {
            return sodium_crypto_sign_detached($input, $this->edDsaKey($privateKey, true));
        }
        if ($this->algorithm->isRsaPss()) {
            return $this->rsaPssPrivateKey($privateKey)->sign($input);
        }

        $key = $this->loadAndValidateKey($privateKey, true);
        if (!openssl_sign($input, $signature, $key, $this->algorithm->opensslAlgorithm()) || !is_string($signature)) {
            throw new ConfigurationException('JWT signing failed.');
        }

        return $signature;
    }

    /**
     * @param array<string, mixed> $header
     */
    private function validateHeader(array $header): ?JwtFailureReason
    {
        if (!isset($header['alg'], $header['typ']) || !is_string($header['alg']) || !is_string($header['typ'])) {
            return JwtFailureReason::MALFORMED;
        }
        if (AsymmetricJwtAlgorithm::tryFrom($header['alg']) === null) {
            return JwtFailureReason::UNSUPPORTED_ALGORITHM;
        }
        if ($header['alg'] !== $this->algorithm->value) {
            return JwtFailureReason::ALGORITHM_MISMATCH;
        }
        if ($this->policy?->acceptsType($header['typ']) !== true) {
            return JwtFailureReason::INVALID_TYPE;
        }
        if (isset($header['cty']) || isset($header['crit'])) {
            return JwtFailureReason::MALFORMED;
        }
        if (isset($header['kid']) && (!is_string($header['kid']) || preg_match('/\A[A-Za-z0-9_-]{1,128}\z/D', $header['kid']) !== 1)) {
            return JwtFailureReason::MALFORMED;
        }

        return null;
    }

    private function validateKey(#[\SensitiveParameter] string $key, bool $private): void
    {
        if ($this->algorithm->isEdDsa()) {
            $this->edDsaKey($key, $private);

            return;
        }
        $this->loadAndValidateKey($key, $private);
        if ($this->algorithm->isRsaPss()) {
            $private ? $this->rsaPssPrivateKey($key) : $this->rsaPssPublicKey($key);
        }
    }

    /**
     * @param array<mixed, mixed> $details
     */
    private function validateKeyDetails(array $details): void
    {
        if (str_starts_with($this->algorithm->value, 'RS') || str_starts_with($this->algorithm->value, 'PS')) {
            if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || !is_int($details['bits'] ?? null) || $details['bits'] < 2048) {
                throw new ConfigurationException('RSA JWT keys must contain at least 2048 bits.');
            }

            return;
        }

        $expectedCurve = match ($this->algorithm) {
            AsymmetricJwtAlgorithm::ES256 => ['prime256v1', 'secp256r1'],
            AsymmetricJwtAlgorithm::ES384 => ['secp384r1'],
            AsymmetricJwtAlgorithm::ES512 => ['secp521r1'],
            AsymmetricJwtAlgorithm::EDDSA => [],
            AsymmetricJwtAlgorithm::PS256,
            AsymmetricJwtAlgorithm::PS384,
            AsymmetricJwtAlgorithm::PS512,
            AsymmetricJwtAlgorithm::RS256,
            AsymmetricJwtAlgorithm::RS384,
            AsymmetricJwtAlgorithm::RS512 => [],
        };
        $ec = $details['ec'] ?? null;
        $curve = is_array($ec) ? ($ec['curve_name'] ?? null) : null;
        if (($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC || !is_string($curve) || !in_array($curve, $expectedCurve, true)) {
            throw new ConfigurationException('EC JWT key curve does not match the configured algorithm.');
        }
    }

    private function verifySignature(#[\SensitiveParameter] string $input, string $signature, string $publicKey): bool
    {
        if ($this->algorithm->isEdDsa()) {
            if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
                return false;
            }

            return sodium_crypto_sign_verify_detached($signature, $input, $this->edDsaKey($publicKey, false));
        }
        if ($this->algorithm->isRsaPss()) {
            return $this->rsaPssPublicKey($publicKey)->verify($input, $signature);
        }

        return openssl_verify(
            $input,
            $signature,
            $this->loadAndValidateKey($publicKey, false),
            $this->algorithm->opensslAlgorithm(),
        ) === 1;
    }
}
