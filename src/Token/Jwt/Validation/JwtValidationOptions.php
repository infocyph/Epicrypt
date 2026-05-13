<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Validation;

final readonly class JwtValidationOptions
{
    public function __construct(
        public bool $strictTyp = false,
        public string $requiredTyp = 'JWT',
        public bool $rejectCriticalHeaders = true,
        public bool $rejectNoneAlgorithm = true,
        public int $leewaySeconds = 0,
        public ?int $maxTokenAgeSeconds = null,
    ) {}
}
