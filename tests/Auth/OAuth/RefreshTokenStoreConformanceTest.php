<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\RefreshTokenStoreInterface;
use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Tests\Support\RefreshTokenStoreConformance;

it('passes the reusable OAuth refresh-token storage conformance suite', function () {
    $suite = new class extends RefreshTokenStoreConformance {
        protected function newStore(): RefreshTokenStoreInterface
        {
            return new InMemoryRefreshTokenStore();
        }
    };

    $suite->assertConforms();
    expect(true)->toBeTrue();
});
