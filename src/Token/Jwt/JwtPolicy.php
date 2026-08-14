<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class JwtPolicy
{
    /** @var array<string, true> */
    private array $requiredClaimSet;

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
        $requiredClaimSet = self::requiredClaimSet($this->requiredClaims);
        self::validateProfile($this->profile, $this->expectedType, $requiredClaimSet);
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
            'at+jwt',
            profile: JwtProfile::OAUTH_ACCESS_TOKEN,
            requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'jti', 'client_id'],
        );
    }

    public static function openIdIdToken(string $issuer, string $clientId): self
    {
        return new self(
            $issuer,
            $clientId,
            'JWT',
            profile: JwtProfile::OPENID_ID_TOKEN,
            requiredClaims: ['iss', 'aud', 'exp', 'iat'],
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
        if ($this->profile === JwtProfile::OAUTH_ACCESS_TOKEN) {
            return in_array(strtolower($type), ['at+jwt', 'application/at+jwt'], true);
        }

        return hash_equals($this->expectedType, $type);
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
    private static function validateProfile(JwtProfile $profile, string $type, array $requiredClaims): void
    {
        if ($profile !== JwtProfile::OAUTH_ACCESS_TOKEN) {
            return;
        }
        if ($type !== 'at+jwt') {
            throw new ConfigurationException('OAuth access-token policies require typ=at+jwt.');
        }
        foreach (['sub', 'iat', 'jti', 'client_id'] as $claim) {
            if (!isset($requiredClaims[$claim])) {
                throw new ConfigurationException(sprintf('OAuth access-token policies must require %s.', $claim));
            }
        }
    }

    private static function validPolicyValue(string $value, int $maximumBytes): bool
    {
        return $value !== ''
            && strlen($value) <= $maximumBytes
            && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
    }
}
