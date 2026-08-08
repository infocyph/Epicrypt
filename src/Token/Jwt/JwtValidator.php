<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Internal\Base64Url;
use Throwable;

/** @internal */
final class JwtValidator
{
    private const array REGISTERED = ['aud' => true, 'exp' => true, 'iat' => true, 'iss' => true, 'jti' => true, 'nbf' => true, 'sub' => true];

    /**
     * @param array<string, mixed> $claims
     * @return JwtFailureReason|array{issuer: string, jwt_id: string, expires_at: int}
     */
    public static function validate(array $claims, JwtPolicy $policy, int $now): JwtFailureReason|array
    {
        $registered = self::validateRegisteredTypes($claims);
        if ($registered instanceof JwtFailureReason) {
            return $registered;
        }

        if (!hash_equals($policy->expectedIssuer, $registered['issuer'])) {
            return JwtFailureReason::INVALID_ISSUER;
        }
        if (!in_array($policy->expectedAudience, $registered['audiences'], true)) {
            return JwtFailureReason::INVALID_AUDIENCE;
        }

        $temporalFailure = self::validateTemporalClaims(
            $registered['issued_at'],
            $registered['not_before'],
            $registered['expires_at'],
            $policy,
            $now,
        );
        if ($temporalFailure !== null) {
            return $temporalFailure;
        }

        if (!self::validJwtId($registered['jwt_id'])) {
            return JwtFailureReason::INVALID_JTI;
        }

        $customFailure = self::validateCustomClaims($claims);
        if ($customFailure !== null) {
            return $customFailure;
        }

        return [
            'issuer' => $registered['issuer'],
            'jwt_id' => $registered['jwt_id'],
            'expires_at' => $registered['expires_at'],
        ];
    }

    private static function isBoundedJsonValue(mixed $value): bool
    {
        try {
            json_encode($value, JSON_THROW_ON_ERROR, 8);

            return true;
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function validateCustomClaims(array $claims): ?JwtFailureReason
    {
        if (count($claims) > 64) {
            return JwtFailureReason::INVALID_CUSTOM_CLAIM;
        }

        foreach ($claims as $name => $value) {
            if (isset(self::REGISTERED[$name])) {
                continue;
            }

            if (!self::validCustomClaim($name, $value)) {
                return JwtFailureReason::INVALID_CUSTOM_CLAIM;
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $claims
     * @return JwtFailureReason|array{issuer: string, subject: string, audiences: list<string>, expires_at: int, not_before: int, issued_at: int, jwt_id: string}
     */
    private static function validateRegisteredTypes(array $claims): JwtFailureReason|array
    {
        if (!isset($claims['iss'], $claims['sub'], $claims['aud'], $claims['exp'], $claims['nbf'], $claims['iat'], $claims['jti'])) {
            return JwtFailureReason::MALFORMED;
        }
        if (!is_string($claims['iss']) || $claims['iss'] === '') {
            return JwtFailureReason::INVALID_ISSUER;
        }
        if (!is_string($claims['sub']) || $claims['sub'] === '' || strlen($claims['sub']) > 255) {
            return JwtFailureReason::INVALID_SUBJECT;
        }
        if (!is_array($claims['aud']) || $claims['aud'] === [] || !array_is_list($claims['aud'])) {
            return JwtFailureReason::INVALID_AUDIENCE;
        }
        $audiences = [];
        foreach ($claims['aud'] as $audience) {
            if (!is_string($audience) || $audience === '') {
                return JwtFailureReason::INVALID_AUDIENCE;
            }
            $audiences[] = $audience;
        }
        if (!is_int($claims['exp']) || !is_int($claims['nbf']) || !is_int($claims['iat'])) {
            return JwtFailureReason::INVALID_LIFETIME;
        }
        if (!is_string($claims['jti']) || $claims['jti'] === '') {
            return JwtFailureReason::INVALID_JTI;
        }

        return [
            'issuer' => $claims['iss'],
            'subject' => $claims['sub'],
            'audiences' => $audiences,
            'expires_at' => $claims['exp'],
            'not_before' => $claims['nbf'],
            'issued_at' => $claims['iat'],
            'jwt_id' => $claims['jti'],
        ];
    }

    private static function validateTemporalClaims(
        int $issuedAt,
        int $notBefore,
        int $expiresAt,
        JwtPolicy $policy,
        int $now,
    ): ?JwtFailureReason {
        if ($issuedAt > $notBefore || $notBefore >= $expiresAt) {
            return JwtFailureReason::INVALID_LIFETIME;
        }
        if (($expiresAt - $issuedAt) > $policy->maximumLifetimeSeconds) {
            return JwtFailureReason::INVALID_LIFETIME;
        }
        if ($issuedAt > ($now + $policy->maximumFutureIssuedAtSeconds)) {
            return JwtFailureReason::ISSUED_IN_FUTURE;
        }
        if ($now < ($notBefore - $policy->leewaySeconds)) {
            return JwtFailureReason::NOT_ACTIVE;
        }
        if ($now >= ($expiresAt + $policy->leewaySeconds)) {
            return JwtFailureReason::EXPIRED;
        }

        return null;
    }

    private static function validCustomClaim(string $name, mixed $value): bool
    {
        return match ($name) {
            'email' => is_string($value) && strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false,
            'name', 'preferred_username' => is_string($value) && $value !== '' && strlen($value) <= 255,
            'roles', 'scope' => is_array($value) && $value !== [] && array_all(
                $value,
                static fn(mixed $item): bool => is_string($item) && $item !== '' && strlen($item) <= 255,
            ),
            default => self::isBoundedJsonValue($value),
        };
    }

    private static function validJwtId(string $jwtId): bool
    {
        try {
            return strlen(Base64Url::decode($jwtId)) >= 24 && strlen($jwtId) <= 128;
        } catch (Throwable) {
            return false;
        }
    }
}
