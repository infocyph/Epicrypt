<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Tests\Support;

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientStoreInterface;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientType;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;
use PHPUnit\Framework\Assert;

abstract class OAuthClientStoreConformance
{
    abstract protected function newStore(OAuthClient $client): OAuthClientStoreInterface;

    final public function assertConforms(): void
    {
        $client = $this->client();
        $store = $this->newStore($client);

        Assert::assertSame($client, $store->find('browser-client'));
        Assert::assertNull($store->find('Browser-Client'));
        Assert::assertNull($store->find('missing-client'));
    }

    private function client(): OAuthClient
    {
        return new OAuthClient(
            clientId: 'browser-client',
            type: OAuthClientType::PUBLIC,
            enabled: false,
            redirectUris: ['https://client.example/callback'],
            grantTypes: [OAuthGrantType::AUTHORIZATION_CODE, OAuthGrantType::REFRESH_TOKEN],
            scopes: ['openid', 'orders:read'],
            audiences: ['orders-api'],
            authenticationMethods: [OAuthClientAuthenticationMethod::NONE],
        );
    }
}
