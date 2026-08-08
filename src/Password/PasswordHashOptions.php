<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;

final readonly class PasswordHashOptions
{
    public function __construct(
        public PasswordHashAlgorithm $algorithm = PasswordHashAlgorithm::ARGON2ID,
        public int $memoryCost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST,
        public int $timeCost = PASSWORD_ARGON2_DEFAULT_TIME_COST,
        public int $threads = PASSWORD_ARGON2_DEFAULT_THREADS,
        public int $bcryptCost = 12,
    ) {
        if (!in_array($this->algorithm->toPasswordAlgorithm(), password_algos(), true)) {
            throw new PasswordHashException(sprintf(
                'Password hashing algorithm "%s" is not available on this platform.',
                $this->algorithm->value,
            ));
        }

        if ($this->memoryCost < 8192 || $this->memoryCost > 1_048_576
            || $this->timeCost < 1 || $this->timeCost > 10
            || $this->threads < 1 || $this->threads > 16) {
            throw new PasswordHashException('Argon2 costs are outside the supported security bounds.');
        }
        if ($this->bcryptCost < 4 || $this->bcryptCost > 31) {
            throw new PasswordHashException('Bcrypt cost must be between 4 and 31.');
        }
    }

    /** @return array<string, int> */
    public function nativeOptions(): array
    {
        return match ($this->algorithm) {
            PasswordHashAlgorithm::BCRYPT => ['cost' => $this->bcryptCost],
            PasswordHashAlgorithm::ARGON2I, PasswordHashAlgorithm::ARGON2ID => [
                'memory_cost' => $this->memoryCost,
                'time_cost' => $this->timeCost,
                'threads' => $this->threads,
            ],
        };
    }
}
