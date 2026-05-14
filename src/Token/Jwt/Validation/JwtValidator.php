<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;
use Infocyph\Epicrypt\Internal\Clock\ClockInterface;
use Infocyph\Epicrypt\Internal\Clock\SystemClock;

final readonly class JwtValidator
{
    public function __construct(
        private ExpectedJwtClaims $expected,
        private JwtValidationOptions $options = new JwtValidationOptions(),
        private IssuerValidator $issuerValidator = new IssuerValidator(),
        private AudienceValidator $audienceValidator = new AudienceValidator(),
        private SubjectValidator $subjectValidator = new SubjectValidator(),
        private ClockInterface $clock = new SystemClock(),
    ) {}

    /**
     * @param array<string, mixed>|object $claims
     */
    public function validate(array|object $claims): void
    {
        $payload = $this->normalizePayload($claims);
        $expirationValidator = new ExpirationValidator(
            $this->options->leewaySeconds,
            $this->options->maxTokenAgeSeconds,
            $this->clock,
        );

        $this->validateRequiredClaims($payload);
        $this->validateExpectedClaims($payload);
        $expirationValidator->validate($payload['nbf'] ?? null, $payload['exp'] ?? null, $payload['iat'] ?? null);
        $this->validateExpectedJwtId($payload);
    }

    /**
     * @param array<string, mixed>|object $claims
     * @return array<string, mixed>
     */
    private function normalizePayload(array|object $claims): array
    {
        $rawPayload = is_object($claims) ? get_object_vars($claims) : $claims;
        $normalized = [];

        foreach ($rawPayload as $key => $value) {
            if (is_string($key)) {
                $normalized[$key] = $value;
            }
        }

        return $normalized;
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateExpectedClaims(array $payload): void
    {
        if ($this->expected->issuer !== null) {
            $this->issuerValidator->validate($this->expected->issuer, $payload['iss'] ?? null);
        }

        if ($this->expected->audience !== null) {
            $this->audienceValidator->validate($this->expected->audience, $payload['aud'] ?? null);
        }

        if ($this->expected->subject !== null) {
            $this->subjectValidator->validate($this->expected->subject, $payload['sub'] ?? null);
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateExpectedJwtId(array $payload): void
    {
        if ($this->expected->jwtId === null) {
            return;
        }

        if (!isset($payload['jti']) || !is_string($payload['jti']) || !hash_equals($this->expected->jwtId, $payload['jti'])) {
            throw new InvalidClaimException('Invalid JWT ID claim.');
        }
    }

    /**
     * @param array<string, mixed> $payload
     */
    private function validateRequiredClaims(array $payload): void
    {
        if ($this->expected->required->issuer && !isset($payload['iss'])) {
            throw new InvalidClaimException('Missing claim: iss');
        }

        if ($this->expected->required->audience && !isset($payload['aud'])) {
            throw new InvalidClaimException('Missing claim: aud');
        }

        if ($this->expected->required->subject && !isset($payload['sub'])) {
            throw new InvalidClaimException('Missing claim: sub');
        }

        if ($this->expected->required->jwtId && !isset($payload['jti'])) {
            throw new InvalidClaimException('Missing claim: jti');
        }
    }
}
