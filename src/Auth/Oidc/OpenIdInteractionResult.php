<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

final readonly class OpenIdInteractionResult
{
    private function __construct(
        public ?OpenIdInteractionRequirement $requirement,
        public ?OpenIdInteractionErrorCode $error,
    ) {}

    public static function require(OpenIdInteractionRequirement $requirement): self
    {
        return new self($requirement, null);
    }

    public static function error(OpenIdInteractionErrorCode $error): self
    {
        return new self(null, $error);
    }

    public function successful(): bool
    {
        return $this->error === null;
    }
}
