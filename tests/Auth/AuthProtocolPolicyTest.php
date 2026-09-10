<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('centralizes shared OAuth identity scope audience and PKCE ceilings', function () {
    expect(AuthProtocolPolicy::validParameterName('client_id'))->toBeTrue()
        ->and(AuthProtocolPolicy::validParameterValue('orders:read orders:write'))->toBeTrue()
        ->and(AuthProtocolPolicy::validParameterValue(str_repeat('a', AuthProtocolPolicy::MAX_PARAMETER_VALUE_BYTES + 1)))->toBeFalse()
        ->and(AuthProtocolPolicy::validText(str_repeat('a', AuthProtocolPolicy::MAX_IDENTIFIER_BYTES), AuthProtocolPolicy::MAX_IDENTIFIER_BYTES))->toBeTrue()
        ->and(AuthProtocolPolicy::validText(str_repeat('a', AuthProtocolPolicy::MAX_IDENTIFIER_BYTES + 1), AuthProtocolPolicy::MAX_IDENTIFIER_BYTES))->toBeFalse()
        ->and(AuthProtocolPolicy::validSha256Base64Url(str_repeat('A', 43)))->toBeTrue()
        ->and(AuthProtocolPolicy::validSha256Base64Url(str_repeat('A', 42)))->toBeFalse()
        ->and(AuthProtocolPolicy::validPkceVerifier(str_repeat('a', 43)))->toBeTrue()
        ->and(AuthProtocolPolicy::validPkceVerifier(str_repeat('a', 42)))->toBeFalse()
        ->and(AuthProtocolPolicy::validPkceVerifier(str_repeat('a', 129)))->toBeFalse();
});

it('normalizes bounded unique scopes and audiences through one policy', function () {
    expect(AuthProtocolPolicy::normalizeScopes(['read', 'orders:write'], 'Scopes'))->toBe(['read', 'orders:write'])
        ->and(AuthProtocolPolicy::normalizeAudiences(['orders-api'], 'Audiences'))->toBe(['orders-api']);

    expect(fn () => AuthProtocolPolicy::normalizeScopes(['read', 'read'], 'Scopes'))->toThrow(ConfigurationException::class)
        ->and(fn () => AuthProtocolPolicy::normalizeScopes([str_repeat('a', AuthProtocolPolicy::MAX_SCOPE_BYTES + 1)], 'Scopes'))->toThrow(ConfigurationException::class)
        ->and(fn () => AuthProtocolPolicy::normalizeAudiences([], 'Audiences'))->toThrow(ConfigurationException::class)
        ->and(fn () => AuthProtocolPolicy::normalizeAudiences(['api', 'api'], 'Audiences'))->toThrow(ConfigurationException::class);
});

it('predefines bounded personal-token ability ceilings without making them public configuration', function () {
    expect(AuthProtocolPolicy::normalizePersonalTokenAbilities(['orders:read', '*']))->toBe(['orders:read', '*'])
        ->and(fn () => AuthProtocolPolicy::normalizePersonalTokenAbilities(['read', 'read']))->toThrow(ConfigurationException::class)
        ->and(fn () => AuthProtocolPolicy::normalizePersonalTokenAbilities([str_repeat('a', AuthProtocolPolicy::MAX_PERSONAL_TOKEN_ABILITY_BYTES + 1)]))->toThrow(ConfigurationException::class);
});
