<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Contract;

use Infocyph\Epicrypt\Password\PasswordVerificationResult;

interface PasswordHasherInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function hashPassword(#[\SensitiveParameter] string $password, array $options = []): string;

    /**
     * @param array<string, mixed> $options
     */
    public function needsRehash(string $hash, array $options = []): bool;

    /**
     * @param array<string, mixed> $options
     */
    public function verifyAndNeedsRehash(#[\SensitiveParameter] string $password, string $hash, array $options = []): PasswordVerificationResult;

    /**
     * @param array<string, mixed> $options
     */
    public function verifyAndRehash(#[\SensitiveParameter] string $password, string $hash, array $options = []): PasswordVerificationResult;

    /**
     * @param array<string, mixed> $options
     */
    public function verifyPassword(#[\SensitiveParameter] string $password, string $hash, array $options = []): bool;
}
