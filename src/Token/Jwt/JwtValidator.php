<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

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
        $registered = self::validateRegisteredTypes($claims, $policy);
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

        if ($registered['jwt_id'] !== null && !self::validJwtId($registered['jwt_id'])) {
            return JwtFailureReason::INVALID_JTI;
        }

        $customFailure = self::validateCustomClaims($claims, $policy->profile);
        if ($customFailure !== null) {
            return $customFailure;
        }

        return [
            'issuer' => $registered['issuer'],
            'jwt_id' => $registered['jwt_id'] ?? '',
            'expires_at' => $registered['expires_at'],
        ];
    }

    /** @return null|list<string> */
    private static function audiences(mixed $audience): ?array
    {
        if (is_string($audience)) {
            return self::validIdentityValue($audience, 2048) ? [$audience] : null;
        }
        if (!is_array($audience) || $audience === [] || count($audience) > 32 || !array_is_list($audience)) {
            return null;
        }

        $audiences = [];
        foreach ($audience as $value) {
            if (!is_string($value) || !self::validIdentityValue($value, 2048)) {
                return null;
            }
            $audiences[] = $value;
        }

        return $audiences;
    }

    private static function failureForClaim(string $claim): JwtFailureReason
    {
        return match ($claim) {
            'iss' => JwtFailureReason::INVALID_ISSUER,
            'sub' => JwtFailureReason::INVALID_SUBJECT,
            'aud' => JwtFailureReason::INVALID_AUDIENCE,
            'exp', 'nbf', 'iat' => JwtFailureReason::INVALID_LIFETIME,
            'jti' => JwtFailureReason::INVALID_JTI,
            'client_id' => JwtFailureReason::INVALID_CLIENT_ID,
            default => JwtFailureReason::MALFORMED,
        };
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
     * @return JwtFailureReason|array{expires_at: int, not_before: ?int, issued_at: ?int}
     */
    private static function normalizeDates(array $claims): JwtFailureReason|array
    {
        $expiresAt = self::numericDate($claims['exp']);
        $notBefore = array_key_exists('nbf', $claims) ? self::numericDate($claims['nbf']) : null;
        $issuedAt = array_key_exists('iat', $claims) ? self::numericDate($claims['iat']) : null;
        if ($expiresAt === null
            || (array_key_exists('nbf', $claims) && $notBefore === null)
            || (array_key_exists('iat', $claims) && $issuedAt === null)) {
            return JwtFailureReason::INVALID_LIFETIME;
        }

        return ['expires_at' => $expiresAt, 'not_before' => $notBefore, 'issued_at' => $issuedAt];
    }

    /**
     * @param array<string, mixed> $claims
     * @return JwtFailureReason|array{issuer: string, subject: ?string, audiences: list<string>}
     */
    private static function normalizeIdentity(array $claims): JwtFailureReason|array
    {
        if (!is_string($claims['iss']) || !self::validIdentityValue($claims['iss'], 2048)) {
            return JwtFailureReason::INVALID_ISSUER;
        }
        $subject = $claims['sub'] ?? null;
        if ($subject !== null && (!is_string($subject) || !self::validIdentityValue($subject, 255))) {
            return JwtFailureReason::INVALID_SUBJECT;
        }
        $audiences = self::audiences($claims['aud']);
        if ($audiences === null) {
            return JwtFailureReason::INVALID_AUDIENCE;
        }

        return ['issuer' => $claims['iss'], 'subject' => $subject, 'audiences' => $audiences];
    }

    private static function numericDate(mixed $value): ?int
    {
        return is_int($value) ? $value : null;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private static function validateCustomClaims(array $claims, JwtProfile $profile): ?JwtFailureReason
    {
        if (count($claims) > 64) {
            return JwtFailureReason::INVALID_CUSTOM_CLAIM;
        }

        foreach ($claims as $name => $value) {
            if (isset(self::REGISTERED[$name])) {
                continue;
            }

            if (!self::validCustomClaim($name, $value, $profile)) {
                return $name === 'scope'
                    ? JwtFailureReason::INVALID_SCOPE
                    : ($name === 'client_id' ? JwtFailureReason::INVALID_CLIENT_ID : JwtFailureReason::INVALID_CUSTOM_CLAIM);
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $claims
     * @return JwtFailureReason|array{issuer: string, subject: ?string, audiences: list<string>, expires_at: int, not_before: ?int, issued_at: ?int, jwt_id: ?string}
     */
    private static function validateRegisteredTypes(array $claims, JwtPolicy $policy): JwtFailureReason|array
    {
        $missingFailure = self::validateRequiredClaims($claims, $policy->requiredClaims);
        if ($missingFailure !== null) {
            return $missingFailure;
        }
        $identity = self::normalizeIdentity($claims);
        if ($identity instanceof JwtFailureReason) {
            return $identity;
        }
        $dates = self::normalizeDates($claims);
        if ($dates instanceof JwtFailureReason) {
            return $dates;
        }

        $jwtId = $claims['jti'] ?? null;
        if ($jwtId !== null && !is_string($jwtId)) {
            return JwtFailureReason::INVALID_JTI;
        }

        return [
            'issuer' => $identity['issuer'],
            'subject' => $identity['subject'],
            'audiences' => $identity['audiences'],
            'expires_at' => $dates['expires_at'],
            'not_before' => $dates['not_before'],
            'issued_at' => $dates['issued_at'],
            'jwt_id' => $jwtId,
        ];
    }

    /**
     * @param array<string, mixed> $claims
     * @param list<string> $requiredClaims
     */
    private static function validateRequiredClaims(array $claims, array $requiredClaims): ?JwtFailureReason
    {
        foreach ($requiredClaims as $claim) {
            if (!array_key_exists($claim, $claims)) {
                return self::failureForClaim($claim);
            }
        }

        return null;
    }

    private static function validateTemporalClaims(
        ?int $issuedAt,
        ?int $notBefore,
        int $expiresAt,
        JwtPolicy $policy,
        int $now,
    ): ?JwtFailureReason {
        if (($issuedAt !== null && $issuedAt >= $expiresAt)
            || ($notBefore !== null && $notBefore >= $expiresAt)
            || ($issuedAt !== null && $notBefore !== null && $issuedAt > $notBefore)) {
            return JwtFailureReason::INVALID_LIFETIME;
        }
        if ($issuedAt !== null && ($expiresAt - $issuedAt) > $policy->maximumLifetimeSeconds) {
            return JwtFailureReason::INVALID_LIFETIME;
        }
        if ($issuedAt !== null && $issuedAt > ($now + $policy->maximumFutureIssuedAtSeconds)) {
            return JwtFailureReason::ISSUED_IN_FUTURE;
        }
        if ($notBefore !== null && $now < ($notBefore - $policy->leewaySeconds)) {
            return JwtFailureReason::NOT_ACTIVE;
        }
        if ($now >= ($expiresAt + $policy->leewaySeconds)) {
            return JwtFailureReason::EXPIRED;
        }

        return null;
    }

    private static function validCustomClaim(string $name, mixed $value, JwtProfile $profile): bool
    {
        return match ($name) {
            'client_id' => is_string($value) && $value !== '' && strlen($value) <= 255,
            'email' => is_string($value) && strlen($value) <= 254 && filter_var($value, FILTER_VALIDATE_EMAIL) !== false,
            'name', 'preferred_username' => is_string($value) && $value !== '' && strlen($value) <= 255,
            'roles' => is_array($value) && $value !== [] && array_is_list($value) && array_all(
                $value,
                static fn(mixed $item): bool => is_string($item) && $item !== '' && strlen($item) <= 255,
            ),
            'scope' => self::validScope($value, $profile),
            default => self::isBoundedJsonValue($value),
        };
    }

    private static function validIdentityValue(string $value, int $maximumBytes): bool
    {
        return $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }

    private static function validJwtId(string $jwtId): bool
    {
        return $jwtId !== '' && strlen($jwtId) <= 128 && preg_match('/[\x00-\x1F\x7F]/', $jwtId) !== 1;
    }

    private static function validScope(mixed $scope, JwtProfile $profile): bool
    {
        if (is_string($scope)) {
            return preg_match('/\A[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*\z/D', $scope) === 1;
        }

        return $profile !== JwtProfile::OAUTH_ACCESS_TOKEN
            && is_array($scope)
            && $scope !== []
            && array_is_list($scope)
            && array_all($scope, static fn(mixed $item): bool => is_string($item) && $item !== '' && strlen($item) <= 255);
    }
}
