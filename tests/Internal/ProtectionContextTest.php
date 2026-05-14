<?php

use Infocyph\Epicrypt\DataProtection\Support\ProtectionContext;
use Infocyph\Epicrypt\Exception\ConfigurationException;

it('normalizes protection context through readonly value object', function () {
    $context = ProtectionContext::fromArray([
        'key_is_binary' => true,
        'nonce_is_binary' => false,
        'aad' => 'meta',
        'key_id' => 'active',
        'purpose' => 'user.email',
    ]);

    expect($context->keyIsBinary)->toBeTrue();
    expect($context->nonceIsBinary)->toBeFalse();
    expect($context->aad)->toBe('meta');
    expect($context->keyId)->toBe('active');
    expect($context->purpose)->toBe('user.email');
    expect($context->toArray())->toBe([
        'key_is_binary' => true,
        'nonce_is_binary' => false,
        'aad' => 'meta',
        'key_id' => 'active',
        'purpose' => 'user.email',
    ]);
});

it('rejects invalid typed protection context inputs', function () {
    expect(fn () => ProtectionContext::fromArray(['key_is_binary' => 'yes']))
        ->toThrow(ConfigurationException::class);
    expect(fn () => ProtectionContext::fromArray(['key_id' => '']))
        ->toThrow(ConfigurationException::class);
    expect(fn () => ProtectionContext::fromArray(['purpose' => '']))
        ->toThrow(ConfigurationException::class);
});
