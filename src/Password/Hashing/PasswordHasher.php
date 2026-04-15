<?php

namespace Infocyph\Epicrypt\Password\Hashing;

use Infocyph\Epicrypt\Contract\PasswordHasherInterface;
use Infocyph\Epicrypt\Exception\Password\PasswordHashException;

final class PasswordHasher implements PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hashPassword(string $password, array $options = []): string
    {
        $algo = $options['algorithm'] ?? PASSWORD_ARGON2ID;

        $hashOptions = [];
        if (isset($options['memory_cost'])) {
            $hashOptions['memory_cost'] = (int) $options['memory_cost'];
        }

        if (isset($options['time_cost'])) {
            $hashOptions['time_cost'] = (int) $options['time_cost'];
        }

        if (isset($options['threads'])) {
            $hashOptions['threads'] = (int) $options['threads'];
        }

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
}
