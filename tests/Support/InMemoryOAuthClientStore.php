<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientStoreInterface;

final class InMemoryOAuthClientStore implements OAuthClientStoreInterface
{
    /** @var array<string, OAuthClient> */
    private array $clients = [];

    /** @param list<OAuthClient> $clients */
    public function __construct(array $clients = [])
    {
        foreach ($clients as $client) {
            $this->clients[$client->clientId] = $client;
        }
    }

    public function find(string $clientId): ?OAuthClient
    {
        return $this->clients[$clientId] ?? null;
    }
}
