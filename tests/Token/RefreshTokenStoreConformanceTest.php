<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Tests\Support\InMemoryRefreshTokenStore;
use Infocyph\Epicrypt\Tests\Support\RefreshTokenStoreConformance;
use Infocyph\Epicrypt\Token\Opaque\RefreshTokenStoreInterface;

it('passes the reusable refresh-token storage conformance suite', function () {
    $suite = new class extends RefreshTokenStoreConformance {
        protected function newStore(): RefreshTokenStoreInterface
        {
            return new InMemoryRefreshTokenStore();
        }
    };

    $suite->assertConforms();
    expect(true)->toBeTrue();
});
