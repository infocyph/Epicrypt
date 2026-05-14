<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use ArrayAccess;
use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Exception\Token\TokenException;
use Infocyph\Epicrypt\Security\KeyRing;
use Infocyph\Epicrypt\Token\Support\TokenKeyCandidates;

trait JwtCommon
{
    /**
     * @var array<string>
     */
    private const array RESERVED_CLAIMS = ['iss', 'aud', 'sub', 'jti', 'iat', 'nbf', 'exp', 'kid'];

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
     * @param iterable<string, string>|KeyRing $keys
     * @return list<array{id: ?string, key: string, active: bool}>
     */
    private function orderedKeyEntries(iterable|KeyRing $keys, string $emptyCandidateMessage, string $missingCandidateMessage): array
    {
        return TokenKeyCandidates::orderedEntries($keys, $emptyCandidateMessage, $missingCandidateMessage);
    }

    /**
     * @param iterable<string, string>|KeyRing $keys
     * @return list<string>
     */
    private function orderedKeys(iterable|KeyRing $keys, string $emptyCandidateMessage, string $missingCandidateMessage): array
    {
        return TokenKeyCandidates::orderedKeys($keys, $emptyCandidateMessage, $missingCandidateMessage);
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
