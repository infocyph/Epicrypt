<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use ArrayAccess;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Contract\JwtTokenInterface;
use Infocyph\Epicrypt\Token\Jwt\Enum\SymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\Support\JwtToken;
use Infocyph\Epicrypt\Token\Jwt\Validation\JwtValidator;
use Infocyph\Epicrypt\Token\Jwt\Validation\RegisteredClaims;
use Throwable;

final readonly class SymmetricJwt implements JwtTokenInterface
{
    /**
     * @var array<string>
     */
    private const array RESERVED_CLAIMS = ['iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'kid'];

    public function __construct(private SymmetricJwtAlgorithm $algorithm = SymmetricJwtAlgorithm::HS512, private ?RegisteredClaims $expectedClaims = null) {}

    public function decode(string $token, mixed $key): object
    {
        $key = $this->requireSupportedKeyType($key);

        if ($this->expectedClaims === null) {
            throw new TokenException('Expected claims are required for JWT decoding.');
        }

        try {
            [$encodedHeader, $encodedPayload, $signature, $header, $payload] = JwtToken::parse($token);

            if (!isset($header['alg']) || !is_string($header['alg'])) {
                throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
            }

            $algorithm = SymmetricJwtAlgorithm::fromHeader($header['alg']);
            if ($algorithm !== $this->algorithm) {
                throw new UnsupportedAlgorithmException('Invalid or unsupported algorithm.');
            }

            $secret = KeyResolver::resolve($key, $header['kid'] ?? null);
            $expected = hash_hmac(
                $algorithm->hmacAlgorithm(),
                $encodedHeader . '.' . $encodedPayload,
                $secret,
                true,
            );

            if (!hash_equals($expected, $signature)) {
                throw new InvalidTokenException('Signature verification failed.');
            }

            new JwtValidator($this->expectedClaims)->validate($payload);

            return (object) $payload;
        } catch (UnsupportedAlgorithmException|KeyResolutionException|InvalidTokenException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidTokenException($e->getMessage(), 0, $e);
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $headers
     */
    public function encode(array $claims, mixed $key, array $headers = []): string
    {
        $key = $this->requireSupportedKeyType($key);

        $registeredClaims = RegisteredClaims::fromArray($claims);
        [$notBefore, $expiresAt] = $this->extractTemporalClaims($claims);
        $keyId = $claims['kid'] ?? null;

        try {
            $secret = KeyResolver::resolve($key, $keyId);
            $algorithm = $this->algorithm;
            $hmacAlgorithm = $algorithm->hmacAlgorithm();

            $payload = [
                'iss' => $registeredClaims->issuer,
                'aud' => $registeredClaims->audience,
                'sub' => $registeredClaims->subject,
                'iat' => time(),
                'nbf' => $notBefore,
                'exp' => $expiresAt,
            ];

            if ($registeredClaims->jwtId !== null) {
                $payload['jti'] = $registeredClaims->jwtId;
            }

            $header = [
                'alg' => $algorithm->value,
                'typ' => 'JWT',
            ];

            if ($keyId !== null) {
                if (!is_string($keyId) || $keyId === '') {
                    throw new InvalidClaimException('Claim "kid" must be a non-empty string when provided.');
                }

                $header['kid'] = $keyId;
            }

            [$encodedHeader, $encodedPayload] = JwtToken::encodeSegments(
                $header + $headers,
                $payload + $this->removeReservedClaims($claims),
            );

            $signature = hash_hmac(
                $hmacAlgorithm,
                $encodedHeader . '.' . $encodedPayload,
                $secret,
                true,
            );

            return $encodedHeader . '.' . $encodedPayload . '.' . Base64Url::encode($signature);
        } catch (UnsupportedAlgorithmException|InvalidClaimException|KeyResolutionException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new TokenException("JWT encoding failed: {$e->getMessage()}", 0, $e);
        }
    }

    public function verify(string $token, mixed $key): bool
    {
        try {
            $this->decode($token, $key);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param array<string, mixed> $claims
     * @return array{int, int}
     */
    private function extractTemporalClaims(array $claims): array
    {
        if (!isset($claims['nbf'], $claims['exp'])) {
            throw new InvalidClaimException('Required claims "nbf" and "exp" are missing.');
        }

        if (!is_numeric($claims['nbf']) || !is_numeric($claims['exp'])) {
            throw new InvalidClaimException('Claims "nbf" and "exp" must be numeric timestamps.');
        }

        if ((int) $claims['exp'] <= (int) $claims['nbf']) {
            throw new InvalidClaimException('Claim "exp" must be greater than "nbf".');
        }

        return [(int) $claims['nbf'], (int) $claims['exp']];
    }

    /**
     * @param array<string, mixed> $claims
     * @return array<string, mixed>
     */
    private function removeReservedClaims(array $claims): array
    {
        return array_diff_key($claims, array_flip(self::RESERVED_CLAIMS));
    }

    /**
     * @return string|array<string, mixed>|ArrayAccess<string, mixed>
     */
    private function requireSupportedKeyType(mixed $key): string|array|ArrayAccess
    {
        if (is_string($key)) {
            return $key;
        }

        if ($key instanceof ArrayAccess) {
            return $key;
        }

        if (is_array($key)) {
            $normalized = [];

            foreach ($key as $keyId => $value) {
                if (!is_string($keyId)) {
                    throw new TokenException('Key-set array must use string key identifiers.');
                }

                $normalized[$keyId] = $value;
            }

            return $normalized;
        }

        throw new TokenException('Key must be a string or key-set.');
    }
}
