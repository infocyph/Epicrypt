<?php

namespace Infocyph\Epicrypt\Password\Support;

final class PasswordStrength
{
    public function score(string $password): int
    {
        $score = 0;

        if (strlen($password) >= 12) {
            $score += 25;
        }

        if (preg_match('/[A-Z]/', $password) === 1) {
            $score += 20;
        }

        if (preg_match('/[a-z]/', $password) === 1) {
            $score += 20;
        }

        if (preg_match('/\d/', $password) === 1) {
            $score += 20;
        }

        if (preg_match('/[^a-zA-Z\d]/', $password) === 1) {
            $score += 15;
        }

        return min($score, 100);
    }
}
