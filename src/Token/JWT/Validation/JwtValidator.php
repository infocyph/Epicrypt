<?php

namespace Infocyph\Epicrypt\Token\JWT\Validation;

use Infocyph\Epicrypt\Exception\Token\InvalidClaimException;

final readonly class JwtValidator
{
    public function __construct(
        private RegisteredClaims $expected,
        private IssuerValidator $issuerValidator = new IssuerValidator(),
        private AudienceValidator $audienceValidator = new AudienceValidator(),
        private SubjectValidator $subjectValidator = new SubjectValidator(),
        private ExpirationValidator $expirationValidator = new ExpirationValidator(),
    ) {}

    /**
     * @param array<string, mixed>|object $claims
     */
    public function validate(array|object $claims): void
    {
        $payload = is_object($claims) ? get_object_vars($claims) : $claims;

        $this->issuerValidator->validate($this->expected->issuer, $payload['iss'] ?? null);
        $this->audienceValidator->validate($this->expected->audience, $payload['aud'] ?? null);
        $this->subjectValidator->validate($this->expected->subject, $payload['sub'] ?? null);
        $this->expirationValidator->validate($payload['nbf'] ?? null, $payload['exp'] ?? null);

        if ($this->expected->jwtId !== null) {
            if (! isset($payload['jti']) || ! is_string($payload['jti']) || ! hash_equals($this->expected->jwtId, $payload['jti'])) {
                throw new InvalidClaimException('Invalid JWT ID claim.');
            }
        }
    }
}
