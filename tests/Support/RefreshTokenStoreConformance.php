<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenGrant;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRecord;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenRotationStatus;
use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenStoreInterface;
use PHPUnit\Framework\Assert;

abstract class RefreshTokenStoreConformance
{
    abstract protected function newStore(): RefreshTokenStoreInterface;

    final public function assertConforms(): void
    {
        $this->assertCreationAndConflict();
        $this->assertAtomicRotationAndReuse();
        $this->assertBindingsAndScopeDoNotConsume();
        $this->assertExpirationAndRevocation();
        $this->assertExactReplacementState();
    }

    private function assertCreationAndConflict(): void
    {
        $store = $this->newStore();
        $current = $this->record('current', 'family-a');
        $sameFamily = $this->record('same-family', 'family-a');
        $collision = $this->record('collision', 'family-b');
        Assert::assertTrue($store->create($current));
        Assert::assertFalse($store->create($current));
        Assert::assertFalse($store->create($sameFamily));
        Assert::assertTrue($store->create($collision));

        $collisionReplacement = $this->replacement($current, tokenId: $collision->tokenId, now: 1_700_000_100);
        Assert::assertSame(RefreshTokenRotationStatus::CONFLICT, $store->rotate($current, $collisionReplacement, 'client', str_repeat('A', 43), 1_700_000_100));
        $successor = $this->replacement($current, 'successor', 1_700_000_100);
        Assert::assertSame(RefreshTokenRotationStatus::ROTATED, $store->rotate($current, $successor, 'client', str_repeat('A', 43), 1_700_000_100));
    }

    private function assertAtomicRotationAndReuse(): void
    {
        $store = $this->newStore();
        $current = $this->record('atomic-current', 'family-c');
        Assert::assertTrue($store->create($current));
        $successor = $this->replacement($current, 'atomic-successor', 1_700_000_100, ['read']);
        Assert::assertSame(RefreshTokenRotationStatus::ROTATED, $store->rotate($current, $successor, 'client', str_repeat('A', 43), 1_700_000_100));
        $losing = $this->replacement($current, 'losing-successor', 1_700_000_101);
        Assert::assertSame(RefreshTokenRotationStatus::REUSED, $store->rotate($current, $losing, 'client', str_repeat('A', 43), 1_700_000_101));
        $afterReuse = $this->replacement($successor, 'after-reuse', 1_700_000_102);
        Assert::assertSame(RefreshTokenRotationStatus::REVOKED, $store->rotate($successor, $afterReuse, 'client', str_repeat('A', 43), 1_700_000_102));
    }

    private function assertBindingsAndScopeDoNotConsume(): void
    {
        $store = $this->newStore();
        $current = $this->record('binding-current', 'family-d');
        Assert::assertTrue($store->create($current));
        Assert::assertSame(RefreshTokenRotationStatus::CLIENT_MISMATCH, $store->rotate($current, $this->replacement($current, 'client-mismatch', 1_700_000_100), 'other', str_repeat('A', 43), 1_700_000_100));
        Assert::assertSame(RefreshTokenRotationStatus::SENDER_MISMATCH, $store->rotate($current, $this->replacement($current, 'sender-mismatch', 1_700_000_100), 'client', str_repeat('B', 43), 1_700_000_100));

        $expandedGrant = new RefreshTokenGrant(
            $current->grant->authorizationId, $current->grant->subject, $current->grant->clientId,
            $current->grant->audiences, ['admin'], $current->grant->expiresAt, $current->grant->dpopKeyThumbprint,
        );
        $expanded = new RefreshTokenRecord($this->tokenId('scope-expansion'), $current->familyId, $expandedGrant, 1_700_000_100, 1_700_000_700);
        Assert::assertSame(RefreshTokenRotationStatus::SCOPE_MISMATCH, $store->rotate($current, $expanded, 'client', str_repeat('A', 43), 1_700_000_100));

        $narrowed = $this->replacement($current, 'narrowed', 1_700_000_100, ['read']);
        Assert::assertSame(RefreshTokenRotationStatus::ROTATED, $store->rotate($current, $narrowed, 'client', str_repeat('A', 43), 1_700_000_100));
        Assert::assertSame(['read'], $narrowed->grant->scopes);
    }

    private function assertExpirationAndRevocation(): void
    {
        $idleStore = $this->newStore();
        $idle = $this->record('idle', 'family-e', idleExpiresAt: 1_700_000_100);
        Assert::assertTrue($idleStore->create($idle));
        Assert::assertSame(RefreshTokenRotationStatus::EXPIRED, $idleStore->rotate($idle, $this->replacement($idle, 'idle-next', 1_700_000_100), 'client', str_repeat('A', 43), 1_700_000_100));

        $familyStore = $this->newStore();
        $family = $this->record('family', 'family-f');
        Assert::assertTrue($familyStore->create($family));
        Assert::assertTrue($familyStore->revokeFamily($family->tokenId, 1_700_000_100));
        Assert::assertSame(RefreshTokenRotationStatus::REVOKED, $familyStore->rotate($family, $this->replacement($family, 'family-next', 1_700_000_100), 'client', str_repeat('A', 43), 1_700_000_100));

        $authorizationStore = $this->newStore();
        $authorization = $this->record('authorization', 'family-g');
        Assert::assertTrue($authorizationStore->create($authorization));
        Assert::assertSame(1, $authorizationStore->revokeAuthorization('authorization-1', 1_700_000_100));
        Assert::assertSame(RefreshTokenRotationStatus::REVOKED, $authorizationStore->rotate($authorization, $this->replacement($authorization, 'authorization-next', 1_700_000_100), 'client', str_repeat('A', 43), 1_700_000_100));
    }

    private function assertExactReplacementState(): void
    {
        $store = $this->newStore();
        $current = $this->record('exact-current', 'family-h');
        Assert::assertTrue($store->create($current));
        $wrongFamily = new RefreshTokenRecord($this->tokenId('wrong-family'), $this->familyId('different-family'), $current->grant, 1_700_000_100, 1_700_000_700);
        Assert::assertSame(RefreshTokenRotationStatus::INVALID, $store->rotate($current, $wrongFamily, 'client', str_repeat('A', 43), 1_700_000_100));
        $valid = $this->replacement($current, 'exact-successor', 1_700_000_100);
        Assert::assertSame(RefreshTokenRotationStatus::ROTATED, $store->rotate($current, $valid, 'client', str_repeat('A', 43), 1_700_000_100));
    }

    private function record(string $seed, string $familySeed, int $idleExpiresAt = 1_700_001_000): RefreshTokenRecord
    {
        return new RefreshTokenRecord(
            $this->tokenId($seed), $this->familyId($familySeed),
            new RefreshTokenGrant('authorization-1', 'subject', 'client', ['api'], ['read', 'write'], 1_700_002_000, str_repeat('A', 43)),
            1_700_000_000, $idleExpiresAt,
        );
    }

    /** @param null|list<string> $scopes */
    private function replacement(RefreshTokenRecord $current, string $seed = 'replacement', int $now = 1_700_000_100, ?array $scopes = null, ?string $tokenId = null): RefreshTokenRecord
    {
        $grant = $scopes === null ? $current->grant : $current->grant->withScopes($scopes);
        return new RefreshTokenRecord($tokenId ?? $this->tokenId($seed), $current->familyId, $grant, $now, min($grant->expiresAt, $now + 600));
    }

    private function familyId(string $seed): string
    {
        return sodium_bin2base64(hash('sha256', $seed, true), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }

    private function tokenId(string $seed): string
    {
        return sodium_bin2base64(substr(hash('sha256', $seed, true), 0, 24), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    }
}
