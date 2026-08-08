<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Generator;

use Infocyph\Epicrypt\Exception\Password\InvalidPasswordException;

final readonly class PasswordGenerator
{
    private const string AMBIGUOUS_DIGIT = '01689';

    private const string AMBIGUOUS_LOWER = 'ilo';

    private const string AMBIGUOUS_UPPER = 'BIO';

    private const string DIGIT = '23456789';

    private const string LOWER = 'abcdefghjkmnpqrstuvwxyz';

    private const string SYMBOL = '!@#$%^&*?.,_-+=~[]{}()';

    private const string UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';

    public function generate(int $length = 16, PasswordPolicy $policy = new PasswordPolicy()): string
    {
        if ($length < $policy->minLength) {
            throw new InvalidPasswordException(sprintf('Password length must be at least %d.', $policy->minLength));
        }
        if ($length < $policy->requiredCharacterClasses()) {
            throw new InvalidPasswordException('Password length cannot satisfy all required character classes.');
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

        $passwordChars = $this->secureShuffle($passwordChars);

        return implode('', $passwordChars);
    }

    private function pick(string $characters): string
    {
        if ($characters === '') {
            throw new InvalidPasswordException('Character pool must be non-empty.');
        }

        return $characters[random_int(0, strlen($characters) - 1)];
    }

    /**
     * @param array<int, string> $items
     * @return array<int, string>
     */
    private function secureShuffle(array $items): array
    {
        for ($index = count($items) - 1; $index > 0; $index--) {
            $swapIndex = random_int(0, $index);
            [$items[$index], $items[$swapIndex]] = [$items[$swapIndex], $items[$index]];
        }

        return $items;
    }
}
