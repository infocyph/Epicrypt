<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Security\ActionToken;
use Infocyph\Epicrypt\Security\CsrfTokenManager;
use Infocyph\Epicrypt\Security\EmailVerificationToken;
use Infocyph\Epicrypt\Security\PasswordResetToken;
use Infocyph\Epicrypt\Security\RememberToken;
use Infocyph\Epicrypt\Security\SignedUrl;
use PhpBench\Attributes as Bench;

#[Bench\Revs(100)]
#[Bench\Iterations(5)]
#[Bench\Warmup(1)]
final class SecurityBench
{
    private ActionToken $actionToken;

    private CsrfTokenManager $csrf;

    private EmailVerificationToken $emailVerificationToken;

    private PasswordResetToken $passwordResetToken;

    private RememberToken $rememberToken;

    private SignedUrl $signedUrl;

    /**
     * @var array<string, string>
     */
    private array $state = [];

    public function __construct()
    {
        $secret = str_repeat('bench-security-secret-', 2);
        $this->signedUrl = new SignedUrl($secret);
        $this->csrf = new CsrfTokenManager($secret, 3600);
        $this->passwordResetToken = new PasswordResetToken($secret, 3600);
        $this->emailVerificationToken = new EmailVerificationToken($secret, 3600);
        $this->rememberToken = new RememberToken($secret, 3600);
        $this->actionToken = new ActionToken($secret, 3600);
    }

    public function setUp(): void
    {
        $this->state['signedUrlValue'] = $this->signedUrl->generate(
            'https://example.com/download',
            ['file' => 'report.csv', 'uid' => 'bench-user'],
            time() + 3600,
        );
        $this->state['csrfToken'] = $this->csrf->issueToken('session-bench');
        $this->state['passwordResetTokenValue'] = $this->passwordResetToken->issue('bench-user');
        $this->state['emailVerificationTokenValue'] = $this->emailVerificationToken->issue('bench-user', 'user@example.com');
        $this->state['rememberTokenValue'] = $this->rememberToken->issue('bench-user', 'device-1');
        $this->state['actionTokenValue'] = $this->actionToken->issue('bench-user', 'delete-account');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchActionTokenVerify(): void
    {
        $this->actionToken->verify($this->state['actionTokenValue'], 'bench-user', 'delete-account');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchCsrfIssue(): void
    {
        $this->csrf->issueToken('session-bench');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchCsrfVerify(): void
    {
        $this->csrf->verifyToken('session-bench', $this->state['csrfToken']);
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchEmailVerificationVerify(): void
    {
        $this->emailVerificationToken->verify(
            $this->state['emailVerificationTokenValue'],
            'bench-user',
            'user@example.com',
        );
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchPasswordResetVerify(): void
    {
        $this->passwordResetToken->verify($this->state['passwordResetTokenValue'], 'bench-user');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchRememberTokenVerify(): void
    {
        $this->rememberToken->verify($this->state['rememberTokenValue'], 'bench-user', 'device-1');
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSignedUrlGenerate(): void
    {
        $this->signedUrl->generate(
            'https://example.com/download',
            ['file' => 'report.csv', 'uid' => 'bench-user'],
            time() + 3600,
        );
    }

    #[Bench\BeforeMethods('setUp')]
    public function benchSignedUrlVerify(): void
    {
        $this->signedUrl->verify($this->state['signedUrlValue']);
    }
}
