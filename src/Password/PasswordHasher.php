<?php

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
        if (! in_array($algo, password_algos(), true)) {
            throw new PasswordHashException('Unsupported password hashing algorithm.');
        }

        $hashOptions = [
            'memory_cost' => (int) ($options['memory_cost'] ?? SecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST),
            'time_cost' => (int) ($options['time_cost'] ?? SecurityPolicy::PASSWORD_DEFAULT_TIME_COST),
            'threads' => (int) ($options['threads'] ?? SecurityPolicy::PASSWORD_DEFAULT_THREADS),
        ];

        $hash = password_hash($password, $algo, $hashOptions);
        if (! is_string($hash)) {
            throw new PasswordHashException('Password hashing failed.');
        }

        return $hash;
    }

    /**
     * @param array<string, mixed> $options
     */
    public function verifyPassword(string $password, string $hash, array $options = []): bool
    {
        return password_verify($password, $hash);
    }

    private function resolveAlgorithm(mixed $algorithm): PasswordHashAlgorithm
    {
        if (! ($algorithm instanceof PasswordHashAlgorithm)) {
            throw new PasswordHashException('Password hashing algorithm must be a PasswordHashAlgorithm enum.');
        }

        return $algorithm;
    }
}
