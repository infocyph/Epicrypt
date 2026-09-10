<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\AuthorizationCodeStoreInterface;
use Infocyph\Epicrypt\Tests\Support\AuthorizationCodeStoreConformance;
use Infocyph\Epicrypt\Tests\Support\InMemoryAuthorizationCodeStore;

it('passes the reusable authorization-code storage conformance suite', function () {
    $suite = new class extends AuthorizationCodeStoreConformance {
        protected function newStore(): AuthorizationCodeStoreInterface
        {
            return new InMemoryAuthorizationCodeStore();
        }
    };

    $suite->assertConforms();
    expect(true)->toBeTrue();
});
