<?php

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\Token\ExpiredTokenException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;

final readonly class SignedPayloadCodec
{
    /**
     * @var array<string>
     */
    private const array SUPPORTED_ALGORITHMS = ['sha256', 'sha512'];

    public function __construct(
        private string $secret,
        private string $algorithm = SecurityPolicy::DEFAULT_SIGNED_PAYLOAD_ALGORITHM,
    ) {
        if ($this->secret === '') {
            throw new InvalidTokenException('Signed payload secret must be non-empty.');
        }

        if (! in_array($this->algorithm, self::SUPPORTED_ALGORITHMS, true)) {
            throw new UnsupportedAlgorithmException('Unsupported signed payload algorithm.');
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function issue(array $claims, ?int $expiresAt = null, ?string $type = null): string
    {
        $header = [
            'alg' => strtoupper($this->algorithm),
            'typ' => 'SPT',
            'v' => SecurityPolicy::SIGNED_PAYLOAD_FORMAT_VERSION,
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
        if (isset($header['v']) && (! is_numeric($header['v']) || (int) $header['v'] !== SecurityPolicy::SIGNED_PAYLOAD_FORMAT_VERSION)) {
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
        return Base64Url::encode(hash_hmac($this->algorithm, $value, $this->secret, true));
    }
}
