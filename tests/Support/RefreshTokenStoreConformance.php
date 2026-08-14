<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Token\Opaque\RefreshTokenGrant;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRecord;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenStoreInterface;
use PHPUnit\Framework\Assert;

/**
 * Reusable contract checks for application RefreshTokenStoreInterface adapters.
 *
 * Extend this class in the adapter's integration-test suite and return a fresh,
 * transaction-capable store from newStore(). Run the suite against the real
 * database engine used in production.
 */
abstract class RefreshTokenStoreConformance
{
    abstract protected function newStore(): RefreshTokenStoreInterface;

    final public function assertConforms(): void
    {
        $this->assertCreationAndConflict();
        $this->assertAtomicRotationAndReuse();
        $this->assertBindingsAndScopeDoNotConsume();
        $this->assertExpirationAndRevocation();
    }

    private function assertCreationAndConflict(): void
    {
        $store = $this->newStore();
        $current = $this->record('current', 'family-a');
        $collision = $this->record('collision', 'family-b');
        Assert::assertTrue($store->create($current));
        Assert::assertFalse($store->create($current));
        Assert::assertTrue($store->create($collision));
        Assert::assertSame(
            RefreshTokenRotationStatus::CONFLICT,
            $store->rotate($current->digest, $collision->digest, 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );
        Assert::assertSame(
            RefreshTokenRotationStatus::ROTATED,
            $store->rotate($current->digest, hash('sha256', 'successor'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );
    }

    private function assertAtomicRotationAndReuse(): void
    {
        $store = $this->newStore();
        $current = $this->record('atomic-current', 'family-c');
        $successorDigest = hash('sha256', 'atomic-successor');
        Assert::assertTrue($store->create($current));
        Assert::assertSame(
            RefreshTokenRotationStatus::ROTATED,
            $store->rotate($current->digest, $successorDigest, 'client', str_repeat('A', 43), ['read'], 1_700_000_100, 600)['status'],
        );
        Assert::assertSame(
            RefreshTokenRotationStatus::REUSED,
            $store->rotate($current->digest, hash('sha256', 'losing-successor'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );
        Assert::assertSame(
            RefreshTokenRotationStatus::REVOKED,
            $store->rotate($successorDigest, hash('sha256', 'after-reuse'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );
    }

    private function assertBindingsAndScopeDoNotConsume(): void
    {
        $store = $this->newStore();
        $current = $this->record('binding-current', 'family-d');
        Assert::assertTrue($store->create($current));
        foreach ([
            [
                $store->rotate($current->digest, hash('sha256', 'client-mismatch'), 'other', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
                RefreshTokenRotationStatus::CLIENT_MISMATCH,
            ],
            [
                $store->rotate($current->digest, hash('sha256', 'sender-mismatch'), 'client', str_repeat('B', 43), null, 1_700_000_100, 600)['status'],
                RefreshTokenRotationStatus::SENDER_MISMATCH,
            ],
            [
                $store->rotate($current->digest, hash('sha256', 'scope-expansion'), 'client', str_repeat('A', 43), ['admin'], 1_700_000_100, 600)['status'],
                RefreshTokenRotationStatus::SCOPE_MISMATCH,
            ],
        ] as [$actual, $expected]) {
            Assert::assertSame($expected, $actual);
        }
        $result = $store->rotate(
            $current->digest,
            hash('sha256', 'narrowed'),
            'client',
            str_repeat('A', 43),
            ['read'],
            1_700_000_100,
            600,
        );
        Assert::assertSame(RefreshTokenRotationStatus::ROTATED, $result['status']);
        Assert::assertSame(['read'], $result['grant']?->scopes);
    }

    private function assertExpirationAndRevocation(): void
    {
        $idleStore = $this->newStore();
        $idle = $this->record('idle', 'family-e', idleExpiresAt: 1_700_000_100);
        Assert::assertTrue($idleStore->create($idle));
        Assert::assertSame(
            RefreshTokenRotationStatus::EXPIRED,
            $idleStore->rotate($idle->digest, hash('sha256', 'idle-next'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );

        $familyStore = $this->newStore();
        $family = $this->record('family', 'family-f');
        Assert::assertTrue($familyStore->create($family));
        Assert::assertTrue($familyStore->revokeFamily($family->digest, 1_700_000_100));
        Assert::assertSame(
            RefreshTokenRotationStatus::REVOKED,
            $familyStore->rotate($family->digest, hash('sha256', 'family-next'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );

        $grantStore = $this->newStore();
        $grant = $this->record('grant', 'family-g');
        Assert::assertTrue($grantStore->create($grant));
        Assert::assertSame(1, $grantStore->revokeGrant('grant-1', 1_700_000_100));
        Assert::assertSame(
            RefreshTokenRotationStatus::REVOKED,
            $grantStore->rotate($grant->digest, hash('sha256', 'grant-next'), 'client', str_repeat('A', 43), null, 1_700_000_100, 600)['status'],
        );
    }

    private function record(string $seed, string $familySeed, int $idleExpiresAt = 1_700_001_000): RefreshTokenRecord
    {
        return new RefreshTokenRecord(
            hash('sha256', $seed),
            substr(sodium_bin2base64(hash('sha256', $familySeed, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING), 0, 43),
            new RefreshTokenGrant(
                'grant-1',
                'subject',
                'client',
                ['api'],
                ['read', 'write'],
                1_700_002_000,
                str_repeat('A', 43),
            ),
            1_700_000_000,
            $idleExpiresAt,
        );
    }
}
