<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClientStoreInterface;
use Infocyph\Epicrypt\Tests\Support\InMemoryOAuthClientStore;
use Infocyph\Epicrypt\Tests\Support\OAuthClientStoreConformance;

it('provides a reusable OAuth client-store conformance contract', function () {
    $suite = new class extends OAuthClientStoreConformance {
        protected function newStore(OAuthClient $client): OAuthClientStoreInterface
        {
            return new InMemoryOAuthClientStore([$client]);
        }
    };

    $suite->assertConforms();
});
