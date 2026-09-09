<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Psr\Clock\ClockInterface;

final readonly class OpenIdIdTokenValidator
{
    private const int MAX_AUDIENCES = 32;

    private const int MAX_AUDIENCE_BYTES = 2048;

    private const int MAX_IDENTIFIER_BYTES = 256;

    public function __construct(private ClockInterface $clock = new SystemClock()) {}

    /** @param array<string, mixed> $claims */
    public function validate(
        array $claims,
        AsymmetricJwtAlgorithm $signingAlgorithm,
        string $clientId,
        #[\SensitiveParameter]
        ?string $nonce = null,
        #[\SensitiveParameter]
        ?string $accessToken = null,
        #[\SensitiveParameter]
        ?string $authorizationCode = null,
        #[\SensitiveParameter]
        ?string $state = null,
        ?int $maximumAuthenticationAge = null,
    ): void {
        $this->validateConfiguration($clientId, $nonce, $maximumAuthenticationAge);
        $this->validateAudience($claims, $clientId);
        $this->validateAuthentication($claims, $nonce, $maximumAuthenticationAge);
        $this->validateHalfHash($claims, 'at_hash', $accessToken, $signingAlgorithm);
        $this->validateHalfHash($claims, 'c_hash', $authorizationCode, $signingAlgorithm);
        $this->validateHalfHash($claims, 's_hash', $state, $signingAlgorithm);
    }

    /** @return list<string> */
    private function audiences(mixed $audience): array
    {
        if (is_string($audience)) {
            if (!$this->isIdentifier($audience, self::MAX_AUDIENCE_BYTES)) {
                throw new InvalidClaimException('OIDC ID token aud has an invalid value.');
            }

            return [$audience];
        }
        if (!is_array($audience) || $audience === [] || !array_is_list($audience) || count($audience) > self::MAX_AUDIENCES) {
            throw new InvalidClaimException('OIDC ID token aud has an invalid shape.');
        }

        $normalized = [];
        $seen = [];
        foreach ($audience as $value) {
            if (!is_string($value) || !$this->isIdentifier($value, self::MAX_AUDIENCE_BYTES) || isset($seen[$value])) {
                throw new InvalidClaimException('OIDC ID token aud contains an invalid or duplicate value.');
            }
            $seen[$value] = true;
            $normalized[] = $value;
        }

        return $normalized;
    }

    private function isIdentifier(string $value, int $maximumBytes): bool
    {
        return $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    /** @param array<string, mixed> $claims */
    private function validateAuthentication(
        array $claims,
        #[\SensitiveParameter]
        ?string $nonce,
        ?int $maximumAuthenticationAge,
    ): void {
        if ($nonce !== null && (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce']))) {
            throw new InvalidClaimException('OIDC ID token nonce does not match.');
        }
        if ($maximumAuthenticationAge === null) {
            return;
        }

        $authTime = $claims['auth_time'] ?? null;
        $now = $this->clock->now()->getTimestamp();
        if (!is_int($authTime) || $authTime > $now || ($now - $authTime) > $maximumAuthenticationAge) {
            throw new InvalidClaimException('OIDC ID token auth_time violates maximum age.');
        }
    }

    /** @param array<string, mixed> $claims */
    private function validateAudience(array $claims, string $clientId): void
    {
        $audiences = $this->audiences($claims['aud'] ?? null);
        if (!in_array($clientId, $audiences, true)) {
            throw new InvalidClaimException('OIDC ID token audience does not contain the client id.');
        }

        $azp = $claims['azp'] ?? null;
        if ((count($audiences) > 1 || $azp !== null)
            && (!is_string($azp) || !$this->isIdentifier($azp, 255) || !hash_equals($clientId, $azp))) {
            throw new InvalidClaimException('OIDC ID token azp is required and must match the client id.');
        }
    }

    private function validateConfiguration(
        string $clientId,
        #[\SensitiveParameter]
        ?string $nonce,
        ?int $maximumAuthenticationAge,
    ): void {
        if (!$this->isIdentifier($clientId, 255)) {
            throw new ConfigurationException('OIDC client id is invalid.');
        }
        if ($nonce !== null && !$this->isIdentifier($nonce, self::MAX_IDENTIFIER_BYTES)) {
            throw new ConfigurationException('OIDC nonce is invalid.');
        }
        if ($maximumAuthenticationAge !== null && ($maximumAuthenticationAge < 0 || $maximumAuthenticationAge > 2_678_400)) {
            throw new ConfigurationException('OIDC maximum authentication age is invalid.');
        }
    }

    /** @param array<string, mixed> $claims */
    private function validateHalfHash(
        array $claims,
        string $claim,
        #[\SensitiveParameter]
        ?string $value,
        AsymmetricJwtAlgorithm $algorithm,
    ): void {
        if ($value === null) {
            return;
        }
        $digest = hash($algorithm->hashAlgorithm(), $value, true);
        $expected = Base64Url::encode(substr($digest, 0, intdiv(strlen($digest), 2)));
        if (!is_string($claims[$claim] ?? null) || !hash_equals($expected, $claims[$claim])) {
            throw new InvalidClaimException(sprintf('OIDC ID token %s does not match.', $claim));
        }
    }
}
