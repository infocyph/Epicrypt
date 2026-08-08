<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class JwtPolicy
{
    public function __construct(
        public string $expectedIssuer,
        public string $expectedAudience,
        public string $expectedType,
        public int $maximumLifetimeSeconds = 900,
        public int $leewaySeconds = 30,
        public int $maximumFutureIssuedAtSeconds = 30,
        public JwtReplayMode $replayMode = JwtReplayMode::NONE,
    ) {
        if ($this->expectedIssuer === '' || $this->expectedAudience === '' || $this->expectedType === '') {
            throw new ConfigurationException('JWT issuer, audience, and type policy values must be non-empty.');
        }
        if ($this->maximumLifetimeSeconds < 1 || $this->leewaySeconds < 0 || $this->maximumFutureIssuedAtSeconds < 0) {
            throw new ConfigurationException('JWT temporal policy values are invalid.');
        }
    }

    public static function accessToken(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'at+jwt');
    }

    public static function emailVerification(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'email-verification+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }

    public static function passwordReset(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'password-reset+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }

    public static function singleUseAction(string $issuer, string $audience): self
    {
        return new self($issuer, $audience, 'epicrypt-action+jwt', replayMode: JwtReplayMode::SINGLE_USE);
    }
}
