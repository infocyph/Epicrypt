<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Benchmarks;

use Infocyph\Epicrypt\Password\Enum\PasswordHashAlgorithm;
use Infocyph\Epicrypt\Password\PasswordHasher;
use Infocyph\Epicrypt\Password\PasswordHashOptions;
use PhpBench\Attributes as Bench;

#[Bench\Revs(1)]
#[Bench\Iterations(3)]
final class PasswordBench
{
    /** @var array<string, PasswordHasher> */
    private array $hashers = [];

    /** @var array<string, string> */
    private array $hashes = [];

    public function setUp(): void
    {
        foreach (PasswordHashAlgorithm::cases() as $algorithm) {
            if (!in_array($algorithm->toPasswordAlgorithm(), password_algos(), true)) {
                continue;
            }

            $this->hashers[$algorithm->value] = new PasswordHasher(new PasswordHashOptions($algorithm));
            $this->hashes[$algorithm->value] = $this->hashers[$algorithm->value]
                ->hashPassword('benchmark password value');
        }
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('passwordAlgorithms')]
    public function benchPasswordHash(array $params): void
    {
        $this->hashers[$params['algorithm']]->hashPassword('benchmark password value');
    }

    #[Bench\BeforeMethods('setUp')]
    #[Bench\ParamProviders('passwordAlgorithms')]
    public function benchPasswordVerify(array $params): void
    {
        $algorithm = $params['algorithm'];
        $this->hashers[$algorithm]->verifyPassword('benchmark password value', $this->hashes[$algorithm]);
    }

    /** @return iterable<string, array{algorithm: string}> */
    public function passwordAlgorithms(): iterable
    {
        foreach (PasswordHashAlgorithm::cases() as $algorithm) {
            if (in_array($algorithm->toPasswordAlgorithm(), password_algos(), true)) {
                yield $algorithm->value => ['algorithm' => $algorithm->value];
            }
        }
    }
}
