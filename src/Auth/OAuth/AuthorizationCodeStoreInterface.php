<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

interface AuthorizationCodeStoreInterface
{
    /**
     * Atomically consume one authenticated authorization-code record.
     *
     * The implementation must locate by record.codeId and compare the exact
     * persisted state to record before mutation. A state mismatch returns INVALID
     * and must not consume the stored code. A previously consumed code returns
     * REPLAYED. An unconsumed code at/after expiresAt returns EXPIRED. Exactly one
     * concurrent caller may transition an active record to CONSUMED.
     *
     * Consumed records must be retained at least through their expiration so
     * replay remains distinguishable while the credential could otherwise have
     * been accepted. Multi-process/distributed adapters require linearizable or
     * transactionally equivalent consume behavior; find-then-delete is invalid.
     */
    public function consume(
        #[\SensitiveParameter]
        AuthorizationCodeRecord $record,
        int $now,
    ): AuthorizationCodeConsumeStatus;

    /**
     * Persist a newly issued authorization-code record.
     *
     * Return false only when codeId already exists. Raw JWE authorization codes
     * are never persisted by this contract.
     */
    public function create(#[\SensitiveParameter] AuthorizationCodeRecord $record): bool;
}
