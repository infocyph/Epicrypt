<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Internal\Enum\SignedPayloadAlgorithm;
use Infocyph\Epicrypt\Internal\Enum\SignedPayloadVersion;
use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final readonly class SignedPayloadCodec
{
    private const int MAX_TOKEN_BYTES = 16 * 1024;

    public function __construct(
        #[\SensitiveParameter]
        private string $secret,
        private SignedPayloadAlgorithm $algorithm = SignedPayloadAlgorithm::SHA512,
        private ClockInterface $clock = new SystemClock(),
    ) {
        SecurityPolicy::assertHmacSecret($this->secret, 'Signed payload secret');
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function issue(#[\SensitiveParameter] array $claims, ?int $expiresAt = null, ?string $type = null): string
    {
        $issuedAt = $this->clock->now()->getTimestamp();
        if ($expiresAt !== null && $expiresAt <= $issuedAt) {
            throw new InvalidTokenException('Signed payload expiration must be after issuance.');
        }

        $header = [
            'alg' => strtoupper($this->algorithm->value),
            'typ' => 'SPT',
            'v' => SignedPayloadVersion::V2->value,
        ];

        if ($type !== null) {
            $header['ctx'] = $type;
        }

        $payload = $claims;
        unset($payload['iat'], $payload['exp']);
        $payload['iat'] = $issuedAt;
        if ($expiresAt !== null) {
            $payload['exp'] = $expiresAt;
        }

        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode(Json::encode($payload));
        $signature = $this->sign($encodedHeader . '.' . $encodedPayload);

        $token = $encodedHeader . '.' . $encodedPayload . '.' . $signature;
        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new InvalidTokenException('Signed payload exceeds the maximum encoded size.');
        }

        return $token;
    }

    /**
     * @return array<string, mixed>
     */
    public function verify(#[\SensitiveParameter] string $token, ?string $expectedType = null): array
    {
        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new InvalidTokenException('Signed payload exceeds the maximum encoded size.');
        }

        $parts = explode('.', $token, 3);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new InvalidTokenException('Invalid signed payload format.');
        }

        [$encodedHeader, $encodedPayload, $givenSignature] = $parts;
        $computedSignature = $this->sign($encodedHeader . '.' . $encodedPayload);

        if (!SecureCompare::equals($computedSignature, $givenSignature)) {
            throw new InvalidTokenException('Invalid signed payload signature.');
        }

        $header = Json::decodeToArray(Base64Url::decode($encodedHeader));
        $this->validateHeader($header, $expectedType);

        $payload = Json::decodeToArray(Base64Url::decode($encodedPayload));
        $this->validateTemporalClaims($payload);

        return $payload;
    }

    private function assertTemporalOrder(?int $issuedAt, ?int $notBefore, ?int $expiresAt): void
    {
        if ($issuedAt !== null && $notBefore !== null && $issuedAt > $notBefore) {
            throw new InvalidTokenException('Signed payload temporal claims are inconsistent.');
        }
        if ($notBefore !== null && $expiresAt !== null && $notBefore >= $expiresAt) {
            throw new InvalidTokenException('Signed payload temporal claims are inconsistent.');
        }
        if ($issuedAt !== null && $expiresAt !== null && $issuedAt >= $expiresAt) {
            throw new InvalidTokenException('Signed payload temporal claims are inconsistent.');
        }
    }

    /** @param array<string, mixed> $payload */
    private function integerClaim(#[\SensitiveParameter] array $payload, string $name): ?int
    {
        if (!array_key_exists($name, $payload)) {
            return null;
        }

        $value = $payload[$name];
        if (!is_int($value)) {
            throw new InvalidTokenException(sprintf('Invalid %s claim.', $name));
        }

        return $value;
    }

    private function sign(#[\SensitiveParameter] string $value): string
    {
        return Base64Url::encode(hash_hmac($this->algorithm->value, $value, $this->secret, true));
    }

    /** @param array<string, mixed> $header */
    private function validateHeader(array $header, ?string $expectedType): void
    {
        $expectedKeys = $expectedType === null ? ['alg', 'typ', 'v'] : ['alg', 'ctx', 'typ', 'v'];
        $actualKeys = array_keys($header);
        sort($actualKeys);
        if ($actualKeys !== $expectedKeys
            || $header['v'] !== SignedPayloadVersion::V2->value
            || $header['typ'] !== 'SPT'
            || $header['alg'] !== strtoupper($this->algorithm->value)
            || ($expectedType !== null && $header['ctx'] !== $expectedType)) {
            throw new InvalidTokenException('Invalid signed payload header.');
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateTemporalClaims(#[\SensitiveParameter] array $payload): void
    {
        $now = $this->clock->now()->getTimestamp();
        $issuedAt = $this->integerClaim($payload, 'iat');
        $notBefore = $this->integerClaim($payload, 'nbf');
        $expiresAt = $this->integerClaim($payload, 'exp');

        if ($notBefore !== null && $now < $notBefore) {
            throw new InvalidTokenException('Token is not yet valid.');
        }

        if ($expiresAt !== null && $now >= $expiresAt) {
            throw new ExpiredTokenException('Token has expired.');
        }

        $this->assertTemporalOrder($issuedAt, $notBefore, $expiresAt);
    }
}
