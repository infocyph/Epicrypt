<?php

namespace Infocyph\Epicrypt\Password\Hashing;

final readonly class PasswordVerifier
{
    public function __construct(
        private PasswordHasher $hasher = new PasswordHasher(),
    ) {}

    public function verify(string $password, string $hash): bool
    {
        return $this->hasher->verifyPassword($password, $hash);
    }
}
