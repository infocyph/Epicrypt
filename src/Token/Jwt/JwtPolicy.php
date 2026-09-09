<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Auth\Token\AuthTokenClass;
use Infocyph\Epicrypt\Exception\ConfigurationException;
use Infocyph\Epicrypt\Security\KeyPurpose;

final readonly class JwtPolicy
{
    /** @var array<string, true> */
    private array $requiredClaimSet;

    public KeyPurpose $keyPurpose;

    /**
     * @param list<string> $requiredClaims
     */
    public function __construct(
        public string $expectedIssuer,
        public string $expectedAudience,
        public string $expectedType,
        public int $maximumLifetimeSeconds = 900,
        public int $leewaySeconds = 30,
        public int $maximumFutureIssuedAtSeconds = 30,
        public JwtReplayMode $replayMode = JwtReplayMode::NONE,
        public JwtProfile $profile = JwtProfile::EPICRYPT,
        public array $requiredClaims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'],
        public ?AuthTokenClass $tokenClass = null,
        ?KeyPurpose $keyPurpose = null,
    ) {
        if (!self::validPolicyValue($this->expectedIssuer, 2048)
            || !self::validPolicyValue($this->expectedAudience, 2048)
            || !self::validPolicyValue($this->expectedType, 128)) {
            throw new ConfigurationException('JWT issuer, audience, and type policy values must be non-empty.');
        }
        if ($this->maximumLifetimeSeconds < 1 || $this->leewaySeconds < 0 || $this->maximumFutureIssuedAtSeconds < 0) {
            throw new ConfigurationException('JWT temporal policy values are invalid.');
        }
        if ($this->requiredClaims === []) {
            throw new ConfigurationException('JWT required claims must be a non-empty list.');
        }

        $classKeyPurpose = $this->tokenClass?->keyPurpose();
        if ($classKeyPurpose !== null && $keyPurpose !== null && $classKeyPurpose !== $keyPurpose) {
            throw new ConfigurationException('JWT key purpose does not match the selected authentication token class.');
        }
        $this->keyPurpose = $keyPurpose ?? $classKeyPurpose ?? KeyPurpose::JWT_SIGNING;

        $requiredClaimSet = self::requiredClaimSet($this->requiredClaims);
        self::validateProfile($this->profile, $this->expectedType, $requiredClaimSet, $this->tokenClass);
        if ($this->replayMode !== JwtReplayMode::NONE && !isset($requiredClaimSet['jti'])) {
            throw new ConfigurationException('Replay-protected JWT policies must require iss, exp, and jti.');
        }
        $this->requiredClaimSet = $requiredClaimSet;
    }

    public static function accessToken(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'at+jwt');
    }

    public static function emailVerification(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'email-verification+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }

    /**
     * @param list<string> $requiredClaims
     */
    public static function generic(
        string $issuer,
        string $audience,
        string $type = 'JWT',
        array $requiredClaims = ['iss', 'aud', 'exp'],
    ): self {
        return new self(
            $issuer,
            $audience,
            $type,
            profile: JwtProfile::GENERIC,
            requiredClaims: $requiredClaims,
        );
    }

    public static function oauthAccessToken(string $issuer, string $audience): self
    {
        return new self(
            $issuer,
            $audience,
            AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType(),
            profile: JwtProfile::OAUTH_ACCESS_TOKEN,
            requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
            tokenClass: AuthTokenClass::OAUTH_ACCESS_TOKEN,
        );
    }

    public static function openIdIdToken(string $issuer, string $clientId): self
    {
        return new self(
            $issuer,
            $clientId,
            AuthTokenClass::OIDC_ID_TOKEN->joseType(),
            profile: JwtProfile::OPENID_ID_TOKEN,
            requiredClaims: ['iss', 'aud', 'exp', 'iat'],
            tokenClass: AuthTokenClass::OIDC_ID_TOKEN,
        );
    }

    public static function passwordReset(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'password-reset+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }

    public static function singleUseAction(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'epicrypt-action+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }

    public function acceptsType(string $type): bool
    {
        return $this->tokenClass !== null
            ? $this->tokenClass->acceptsJoseType($type)
            : hash_equals($this->expectedType, $type);
    }

    public function requires(string $claim): bool
    {
        return isset($this->requiredClaimSet[$claim]);
    }

    /**
     * @param list<string> $claims
     * @return array<string, true>
     */
    private static function requiredClaimSet(array $claims): array
    {
        $set = [];
        foreach ($claims as $claim) {
            if (!in_array($claim, ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'client_id'], true)) {
                throw new ConfigurationException(sprintf('Unsupported required JWT claim "%s".', $claim));
            }
            if (isset($set[$claim])) {
                throw new ConfigurationException(sprintf('Duplicate required JWT claim "%s".', $claim));
            }
            $set[$claim] = true;
        }
        foreach (['iss', 'aud', 'exp'] as $claim) {
            if (!isset($set[$claim])) {
                throw new ConfigurationException(sprintf('JWT policies must require %s.', $claim));
            }
        }

        return $set;
    }

    /** @param array<string, true> $requiredClaims */
    private static function validateProfile(
        JwtProfile $profile,
        string $type,
        array $requiredClaims,
        ?AuthTokenClass $tokenClass,
    ): void {
        if ($tokenClass !== null && !$tokenClass->acceptsJoseType($type)) {
            throw new ConfigurationException('JWT type does not match the selected authentication token class.');
        }

        if ($profile === JwtProfile::OAUTH_ACCESS_TOKEN) {
            if ($tokenClass !== AuthTokenClass::OAUTH_ACCESS_TOKEN) {
                throw new ConfigurationException('OAuth access-token policies require the OAuth access-token class.');
            }
            if ($type !== AuthTokenClass::OAUTH_ACCESS_TOKEN->joseType()) {
                throw new ConfigurationException('OAuth access-token policies require typ=at+jwt.');
            }
            foreach (['sub', 'iat', 'jti', 'client_id'] as $claim) {
                if (!isset($requiredClaims[$claim])) {
                    throw new ConfigurationException(sprintf('OAuth access-token policies must require %s.', $claim));
                }
            }

            return;
        }

        if ($profile === JwtProfile::OPENID_ID_TOKEN) {
            if ($tokenClass !== AuthTokenClass::OIDC_ID_TOKEN) {
                throw new ConfigurationException('OpenID ID-token policies require the OIDC ID-token class.');
            }
            if ($type !== AuthTokenClass::OIDC_ID_TOKEN->joseType()) {
                throw new ConfigurationException('OpenID ID-token policies require typ=JWT.');
            }
            if (!isset($requiredClaims['iat'])) {
                throw new ConfigurationException('OpenID ID-token policies must require iat.');
            }

            return;
        }

        if ($tokenClass !== null) {
            throw new ConfigurationException('Authentication token classes require a matching JWT profile.');
        }
    }

    private static function validPolicyValue(string $value, int $maximumBytes): bool
    {
        return $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }
}
