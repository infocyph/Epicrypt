<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

use Infocyph\Epicrypt\Exception\Password\PasswordHashException;
use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;

final readonly class PasswordHasher
{
    public function __construct(private PasswordHashOptions $options = new PasswordHashOptions()) {}

    public function hashPassword(#[\SensitiveParameter] string $password): string
    {
        $this->assertPasswordSupported($password);

        return password_hash(
            $password,
            $this->options->algorithm->toPasswordAlgorithm(),
            $this->options->nativeOptions(),
        );
    }

    public function needsRehash(string $hash): bool
    {
        return password_needs_rehash(
            $hash,
            $this->options->algorithm->toPasswordAlgorithm(),
            $this->options->nativeOptions(),
        );
    }

    public function verifyAndNeedsRehash(
        #[\SensitiveParameter]
        string $password,
        string $hash,
    ): PasswordVerificationResult {
        if (!$this->verifyPassword($password, $hash)) {
            return new PasswordVerificationResult(false, false);
        }

        return new PasswordVerificationResult(true, $this->needsRehash($hash));
    }

    public function verifyAndRehash(
        #[\SensitiveParameter]
        string $password,
        string $hash,
    ): PasswordVerificationResult {
        $result = $this->verifyAndNeedsRehash($password, $hash);
        if (!$result->verified || !$result->needsRehash) {
            return $result;
        }

        return new PasswordVerificationResult(true, true, $this->hashPassword($password));
    }

    public function verifyPassword(#[\SensitiveParameter] string $password, string $hash): bool
    {
        if (str_starts_with($hash, '$2') && strlen($password) > 72) {
            return false;
        }

        return password_verify($password, $hash);
    }

    private function assertPasswordSupported(string $password): void
    {
        if ($this->options->algorithm === PasswordHashAlgorithm::BCRYPT && strlen($password) > 72) {
            throw new PasswordHashException('Bcrypt passwords cannot exceed 72 bytes.');
        }
    }
}
