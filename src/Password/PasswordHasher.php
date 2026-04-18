<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Internal\SecurityPolicy;
use Infocyph\Epicrypt\Password\Contract\PasswordHasherInterface;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Security\Policy\SecurityProfile;

final class PasswordHasher implements PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hashPassword(string $password, array $options = []): string
    {
        [$algorithm, $hashOptions] = $this->resolveHashConfiguration($options);
        $algo = $algorithm->toPasswordAlgorithm();
        if (!in_array($algo, password_algos(), true)) {
            throw new PasswordHashException('Unsupported password hashing algorithm.');
        }

        return password_hash($password, $algo, $hashOptions);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function needsRehash(string $hash, array $options = []): bool
    {
        [$algorithm, $hashOptions] = $this->resolveHashConfiguration($options);

        return password_needs_rehash($hash, $algorithm->toPasswordAlgorithm(), $hashOptions);
    }

    /**
     * @param array<string, mixed> $options
     */
    public function verifyAndNeedsRehash(string $password, string $hash, array $options = []): PasswordVerificationResult
    {
        $verified = $this->verifyPassword($password, $hash, $options);
        if (!$verified) {
            return new PasswordVerificationResult(false, false);
        }

        return new PasswordVerificationResult(true, $this->needsRehash($hash, $options));
    }

    /**
     * @param array<string, mixed> $options
     */
    public function verifyAndRehash(string $password, string $hash, array $options = []): PasswordVerificationResult
    {
        $result = $this->verifyAndNeedsRehash($password, $hash, $options);
        if (!$result->verified || !$result->needsRehash) {
            return $result;
        }

        return new PasswordVerificationResult(
            true,
            true,
            $this->hashPassword($password, $options),
        );
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

    /**
     * @param array<string, mixed> $options
     * @return array{PasswordHashAlgorithm, array<string, int>}
     */
    private function resolveHashConfiguration(array $options): array
    {
        $profile = $options['profile'] ?? null;
        if ($profile !== null && !$profile instanceof SecurityProfile) {
            throw new PasswordHashException('Password hashing profile must be a SecurityProfile enum.');
        }

        $profileOptions = ($profile ?? SecurityProfile::MODERN)->passwordHashOptions();
        $mergedOptions = array_replace($profileOptions, $options);
        $algorithm = $this->resolveAlgorithm($mergedOptions['algorithm'] ?? PasswordHashAlgorithm::ARGON2ID);

        return [
            $algorithm,
            [
                'memory_cost' => $this->intOption($mergedOptions, 'memory_cost', SecurityPolicy::PASSWORD_DEFAULT_MEMORY_COST),
                'time_cost' => $this->intOption($mergedOptions, 'time_cost', SecurityPolicy::PASSWORD_DEFAULT_TIME_COST),
                'threads' => $this->intOption($mergedOptions, 'threads', SecurityPolicy::PASSWORD_DEFAULT_THREADS),
            ],
        ];
    }
}
