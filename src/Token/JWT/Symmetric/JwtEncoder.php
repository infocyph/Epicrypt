<?php

namespace Infocyph\Epicrypt\Token\JWT\Symmetric;

use ArrayAccess;
use Infocyph\Epicrypt\Contract\TokenEncoderInterface;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Exception\Token\UnsupportedAlgorithmException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\JWT\Key\KeyResolver;
use Infocyph\Epicrypt\Token\JWT\Support\AlgorithmMap;
use Infocyph\Epicrypt\Token\JWT\Support\JwtToken;
use Infocyph\Epicrypt\Token\JWT\Validation\RegisteredClaims;
use Throwable;

final readonly class JwtEncoder implements TokenEncoderInterface
{
    /**
     * @var array<string>
     */
    private const array RESERVED_CLAIMS = ['iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'kid'];

    public function __construct(
        private string $algorithm = 'HS512',
    ) {}

    /**
     * @param array<string, mixed> $claims
     * @param string|array<string, mixed>|ArrayAccess<string, mixed> $key
     * @param array<string, mixed> $headers
     */
    public function encode(array $claims, mixed $key, array $headers = []): string
    {
        if (! is_string($key) && ! is_array($key) && ! ($key instanceof ArrayAccess)) {
            throw new TokenException('Key must be a string or key-set.');
        }

        $registeredClaims = RegisteredClaims::fromArray($claims);
        [$notBefore, $expiresAt] = $this->extractTemporalClaims($claims);
        $keyId = $claims['kid'] ?? null;

        try {
            $secret = KeyResolver::resolve($key, $keyId);
            $algorithm = strtoupper($this->algorithm);
            $hmacAlgorithm = AlgorithmMap::hmac($algorithm);

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
                'alg' => $algorithm,
                'typ' => 'JWT',
            ];

            if ($keyId !== null) {
                $header['kid'] = (string) $keyId;
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

    /**
     * @param array<string, mixed> $claims
     * @return array{int, int}
     */
    private function extractTemporalClaims(array $claims): array
    {
        if (! isset($claims['nbf'], $claims['exp'])) {
            throw new InvalidClaimException('Required claims "nbf" and "exp" are missing.');
        }

        if (! is_numeric($claims['nbf']) || ! is_numeric($claims['exp'])) {
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
}
