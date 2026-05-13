<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password;

final class PasswordStrength
{
    /**
     * @param array{email?: mixed, username?: mixed} $context
     */
    public function score(string $password, array $context = []): int
    {
        $score = 0;
        $length = strlen($password);

        $score += min(40, max(0, ($length - 8) * 4));

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

        $score -= $this->repetitionPenalty($password);
        $score -= $this->sequentialPenalty($password);
        $score -= $this->commonPatternPenalty($password);
        $score -= $this->identityPenalty($password, $context);

        return min($score, 100);
    }

    private function commonPatternPenalty(string $password): int
    {
        $lower = strtolower($password);
        $patterns = ['password', 'welcome', 'admin', 'qwerty', 'letmein', '123456', 'iloveyou'];
        foreach ($patterns as $pattern) {
            if (str_contains($lower, $pattern)) {
                return 20;
            }
        }

        return 0;
    }

    /**
     * @param array{email?: mixed, username?: mixed} $context
     */
    private function identityPenalty(string $password, array $context): int
    {
        $passwordLower = strtolower($password);
        $candidates = [];

        if (isset($context['email']) && is_string($context['email']) && $context['email'] !== '') {
            $candidates[] = strtolower($context['email']);
            $emailLocal = explode('@', strtolower($context['email']), 2)[0];
            if ($emailLocal !== '') {
                $candidates[] = $emailLocal;
            }
        }

        if (isset($context['username']) && is_string($context['username']) && $context['username'] !== '') {
            $candidates[] = strtolower($context['username']);
        }

        foreach ($candidates as $candidate) {
            if (str_contains($passwordLower, $candidate)) {
                return 20;
            }
        }

        return 0;
    }

    private function repetitionPenalty(string $password): int
    {
        $counts = count_chars($password, 1);
        $penalty = 0;
        foreach ($counts as $count) {
            if ($count > 2) {
                $penalty += ($count - 2) * 2;
            }
        }

        return min($penalty, 20);
    }

    private function sequentialPenalty(string $password): int
    {
        $lower = strtolower($password);
        $sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiopasdfghjklzxcvbnm'];
        foreach ($sequences as $sequence) {
            for ($index = 0; $index <= strlen($sequence) - 4; $index++) {
                $chunk = substr($sequence, $index, 4);
                if (str_contains($lower, $chunk)) {
                    return 15;
                }
            }
        }

        return 0;
    }
}
