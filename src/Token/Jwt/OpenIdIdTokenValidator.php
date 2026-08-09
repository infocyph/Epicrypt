<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Internal\Base64Url;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;

final class OpenIdIdTokenValidator
{
    /** @param array<string, mixed> $claims */
    public function validate(
        array $claims,
        AsymmetricJwtAlgorithm $signingAlgorithm,
        string $clientId,
        ?string $nonce = null,
        ?string $accessToken = null,
        ?string $authorizationCode = null,
        ?string $state = null,
        ?int $maximumAuthenticationAge = null,
        ?int $now = null,
    ): void {
        $audiences = $this->audiences($claims['aud'] ?? null);
        if (!in_array($clientId, $audiences, true)) {
            throw new InvalidClaimException('OIDC ID token audience does not contain the client id.');
        }
        $azp = $claims['azp'] ?? null;
        if ((count($audiences) > 1 || $azp !== null) && (!is_string($azp) || !hash_equals($clientId, $azp))) {
            throw new InvalidClaimException('OIDC ID token azp is required and must match the client id.');
        }
        if ($nonce !== null && (!is_string($claims['nonce'] ?? null) || !hash_equals($nonce, $claims['nonce']))) {
            throw new InvalidClaimException('OIDC ID token nonce does not match.');
        }
        if ($maximumAuthenticationAge !== null) {
            $authTime = $claims['auth_time'] ?? null;
            if (!is_int($authTime) || $authTime > ($now ?? time()) || (($now ?? time()) - $authTime) > $maximumAuthenticationAge) {
                throw new InvalidClaimException('OIDC ID token auth_time violates maximum age.');
            }
        }
        $this->validateHalfHash($claims, 'at_hash', $accessToken, $signingAlgorithm);
        $this->validateHalfHash($claims, 'c_hash', $authorizationCode, $signingAlgorithm);
        $this->validateHalfHash($claims, 's_hash', $state, $signingAlgorithm);
    }

    /** @return list<string> */
    private function audiences(mixed $audience): array
    {
        if (is_string($audience) && $audience !== '') {
            return [$audience];
        }
        if (!is_array($audience) || $audience === [] || !array_is_list($audience)
            || !array_all($audience, static fn(mixed $value): bool => is_string($value) && $value !== '')) {
            throw new InvalidClaimException('OIDC ID token aud has an invalid shape.');
        }

        $normalized = [];
        foreach ($audience as $value) {
            if (!is_string($value)) {
                throw new InvalidClaimException('OIDC ID token aud must contain strings.');
            }
            $normalized[] = $value;
        }

        return $normalized;
    }

    /** @param array<string, mixed> $claims */
    private function validateHalfHash(
        array $claims,
        string $claim,
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
