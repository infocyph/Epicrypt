<?php

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Internal\Enum\SignedPayloadAlgorithm;
use Infocyph\Epicrypt\Internal\Enum\SignedPayloadVersion;

/**
 * @internal
 */
final readonly class SignedPayloadCodec
{
    public function __construct(
        private string $secret,
        private SignedPayloadAlgorithm $algorithm = SignedPayloadAlgorithm::SHA512,
    ) {
        if ($this->secret === '') {
            throw new InvalidTokenException('Signed payload secret must be non-empty.');
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function issue(array $claims, ?int $expiresAt = null, ?string $type = null): string
    {
        $header = [
            'alg' => strtoupper($this->algorithm->value),
            'typ' => 'SPT',
            'v' => SignedPayloadVersion::V1->value,
        ];

        if ($type !== null) {
            $header['ctx'] = $type;
        }

        $payload = $claims;
        $payload['iat'] = time();
        if ($expiresAt !== null) {
            $payload['exp'] = $expiresAt;
        }

        $encodedHeader = Base64Url::encode(Json::encode($header));
        $encodedPayload = Base64Url::encode(Json::encode($payload));
        $signature = $this->sign($encodedHeader . '.' . $encodedPayload);

        return $encodedHeader . '.' . $encodedPayload . '.' . $signature;
    }

    /**
     * @return array<string, mixed>
     */
    public function verify(string $token, ?string $expectedType = null): array
    {
        $parts = explode('.', $token, 3);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new InvalidTokenException('Invalid signed payload format.');
        }

        [$encodedHeader, $encodedPayload, $givenSignature] = $parts;
        $computedSignature = $this->sign($encodedHeader . '.' . $encodedPayload);

        if (! SecureCompare::equals($computedSignature, $givenSignature)) {
            throw new InvalidTokenException('Invalid signed payload signature.');
        }

        $header = Json::decodeToArray(Base64Url::decode($encodedHeader));
        if (isset($header['v']) && (! is_numeric($header['v']) || (int) $header['v'] !== SignedPayloadVersion::V1->value)) {
            throw new InvalidTokenException('Unsupported signed payload version.');
        }

        if ($expectedType !== null && ($header['ctx'] ?? null) !== $expectedType) {
            throw new InvalidTokenException('Invalid signed payload context.');
        }

        $payload = Json::decodeToArray(Base64Url::decode($encodedPayload));
        if (isset($payload['exp']) && is_numeric($payload['exp']) && time() > (int) $payload['exp']) {
            throw new ExpiredTokenException('Token has expired.');
        }

        return $payload;
    }

    private function sign(string $value): string
    {
        return Base64Url::encode(hash_hmac($this->algorithm->value, $value, $this->secret, true));
    }
}
