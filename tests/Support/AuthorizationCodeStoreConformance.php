<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeConsumeStatus;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeRecord;
use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeStoreInterface;
use PHPUnit\Framework\Assert;

abstract class AuthorizationCodeStoreConformance
{
    abstract protected function newStore(): AuthorizationCodeStoreInterface;

    final public function assertConforms(): void
    {
        $this->assertCreationUniqueness();
        $this->assertExactStateAndOneTimeConsume();
        $this->assertExpiryDoesNotConsumeEarly();
    }

    private function assertCreationUniqueness(): void
    {
        $store = $this->newStore();
        $record = $this->record('code-a');
        Assert::assertTrue($store->create($record));
        Assert::assertFalse($store->create($record));
    }

    private function assertExactStateAndOneTimeConsume(): void
    {
        $store = $this->newStore();
        $record = $this->record('code-b');
        Assert::assertTrue($store->create($record));

        $mismatch = new AuthorizationCodeRecord(
            $record->codeId,
            $record->authorizationId,
            $record->expiresAt,
            hash('sha256', 'different-state'),
        );
        Assert::assertSame(AuthorizationCodeConsumeStatus::INVALID, $store->consume($mismatch, 1_700_000_100));
        Assert::assertSame(AuthorizationCodeConsumeStatus::CONSUMED, $store->consume($record, 1_700_000_100));
        Assert::assertSame(AuthorizationCodeConsumeStatus::REPLAYED, $store->consume($record, 1_700_000_101));
    }

    private function assertExpiryDoesNotConsumeEarly(): void
    {
        $store = $this->newStore();
        $record = $this->record('code-c', expiresAt: 1_700_000_100);
        Assert::assertTrue($store->create($record));
        Assert::assertSame(AuthorizationCodeConsumeStatus::EXPIRED, $store->consume($record, 1_700_000_100));
    }

    private function record(string $seed, int $expiresAt = 1_700_000_600): AuthorizationCodeRecord
    {
        $codeId = sodium_bin2base64(
            substr(hash('sha256', $seed, true), 0, 24),
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING,
        );

        return new AuthorizationCodeRecord(
            $codeId,
            'authorization-1',
            $expiresAt,
            hash('sha256', 'state:' . $seed),
        );
    }
}
