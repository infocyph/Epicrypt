<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Password\Contract\PasswordHasherInterface;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;

final class PasswordHasher implements PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hashPassword(string $password, array $options = []): string
    {
        $algorithm = $this->resolveAlgorithm($options['algorithm'] ?? PasswordHashAlgorithm::ARGON2ID);
        $algo = $algorithm->toPasswordAlgorithm();
        if (!in_array($algo, password_algos(), true)) {
            throw new PasswordHashException('Unsupported password hashing algorithm.');
        }

        $hashOptions = [
            'memory_cost' => $this->intOption($options, 'memory_cost', SecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST),
            'time_cost' => $this->intOption($options, 'time_cost', SecurityPolicy::PASSWORD_DEFAULT_TIME_COST),
            'threads' => $this->intOption($options, 'threads', SecurityPolicy::PASSWORD_DEFAULT_THREADS),
        ];

        return password_hash($password, $algo, $hashOptions);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function verifyPassword(string $password, string $hash, array $options = []): bool
    {
        unset($options);

        return password_verify($password, $hash);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function intOption(array $options, string $key, int $default): int
    {
        $value = $options[$key] ?? $default;
        if (!is_int($value)) {
            throw new PasswordHashException(sprintf('Hash option "%s" must be an integer.', $key));
        }
        if ($value < 1) {
            throw new PasswordHashException(sprintf('Hash option "%s" must be at least 1.', $key));
        }

        return $value;
    }

    private function resolveAlgorithm(mixed $algorithm): PasswordHashAlgorithm
    {
        if (!($algorithm instanceof PasswordHashAlgorithm)) {
            throw new PasswordHashException('Password hashing algorithm must be a PasswordHashAlgorithm enum.');
        }

        return $algorithm;
    }
}
