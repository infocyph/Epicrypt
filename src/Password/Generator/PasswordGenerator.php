<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Generator;

use Infocyph\Epicrypt\Exception\Password\InvalidPasswordException;
use Infocyph\Epicrypt\Password\Contract\PasswordGeneratorInterface;

final readonly class PasswordGenerator implements PasswordGeneratorInterface
{
    private const string AMBIGUOUS_DIGIT = '01689';

    private const string AMBIGUOUS_LOWER = 'ilo';

    private const string AMBIGUOUS_UPPER = 'BIO';

    private const string DIGIT = '23456789';

    private const string LOWER = 'abcdefghjkmnpqrstuvwxyz';

    private const string SYMBOL = '!@#$%^&*?.,_-+=~[]{}()';

    private const string UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';

    /**
     * @param array<string, mixed> $options
     */
    public function generate(int $length = 16, array $options = []): string
    {
        $policy = new PasswordPolicy(
            minLength: $this->intOption($options, 'min_length', 12),
            requireUpper: $this->boolOption($options, 'require_upper', true),
            requireLower: $this->boolOption($options, 'require_lower', true),
            requireDigit: $this->boolOption($options, 'require_digit', true),
            requireSymbol: $this->boolOption($options, 'require_symbol', true),
            includeAmbiguous: $this->boolOption($options, 'include_ambiguous', false),
        );

        if ($length < $policy->minLength) {
            throw new InvalidPasswordException(sprintf('Password length must be at least %d.', $policy->minLength));
        }

        $upper = $policy->includeAmbiguous ? self::UPPER . self::AMBIGUOUS_UPPER : self::UPPER;
        $lower = $policy->includeAmbiguous ? self::LOWER . self::AMBIGUOUS_LOWER : self::LOWER;
        $digit = $policy->includeAmbiguous ? self::DIGIT . self::AMBIGUOUS_DIGIT : self::DIGIT;

        $pool = '';
        $required = [];

        if ($policy->requireUpper) {
            $required[] = $this->pick($upper);
            $pool .= $upper;
        }

        if ($policy->requireLower) {
            $required[] = $this->pick($lower);
            $pool .= $lower;
        }

        if ($policy->requireDigit) {
            $required[] = $this->pick($digit);
            $pool .= $digit;
        }

        if ($policy->requireSymbol) {
            $required[] = $this->pick(self::SYMBOL);
            $pool .= self::SYMBOL;
        }

        if ($pool === '') {
            throw new InvalidPasswordException('At least one character class must be enabled.');
        }

        $passwordChars = $required;
        while (count($passwordChars) < $length) {
            $passwordChars[] = $this->pick($pool);
        }

        shuffle($passwordChars);

        return implode('', $passwordChars);
    }

    /**
     * @param array<string, mixed> $options
     */
    private function boolOption(array $options, string $key, bool $default): bool
    {
        $value = $options[$key] ?? $default;
        if (!is_bool($value)) {
            throw new InvalidPasswordException(sprintf('Option "%s" must be a boolean.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $options
     */
    private function intOption(array $options, string $key, int $default): int
    {
        $value = $options[$key] ?? $default;
        if (!is_int($value)) {
            throw new InvalidPasswordException(sprintf('Option "%s" must be an integer.', $key));
        }

        return $value;
    }

    private function pick(string $characters): string
    {
        if ($characters === '') {
            throw new InvalidPasswordException('Character pool must be non-empty.');
        }

        return $characters[random_int(0, strlen($characters) - 1)];
    }
}
