<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Token\Jwt\Support\PublicUnicastAddress;

it('rejects non-public destinations including multicast and mapped forms', function (string $address) {
    expect(PublicUnicastAddress::allows($address))->toBeFalse();
})->with([
    'private' => ['10.0.0.1'],
    'loopback' => ['127.0.0.1'],
    'shared' => ['100.64.0.1'],
    'benchmark' => ['198.18.0.1'],
    'documentation' => ['192.0.2.1'],
    'ipv4 multicast start' => ['224.0.0.0'],
    'ipv4 multicast end' => ['239.255.255.255'],
    'ipv6 documentation' => ['2001:db8::1'],
    'ipv6 multicast' => ['ff02::1'],
    'mapped private' => ['::ffff:10.0.0.1'],
    'mapped multicast' => ['::ffff:224.0.0.1'],
    'mapped documentation' => ['::ffff:192.0.2.1'],
    'link-local' => ['169.254.169.254'],
    'reserved upper IPv4' => ['240.0.0.1'],
    'limited broadcast' => ['255.255.255.255'],
    'ipv4 unspecified' => ['0.0.0.0'],
    'ipv6 unique local' => ['fc00::1'],
    'unspecified' => ['::'],
]);

it('accepts global unicast IPv4 and IPv6 addresses', function (string $address) {
    expect(PublicUnicastAddress::allows($address))->toBeTrue();
})->with([
    'public ipv4' => ['8.8.8.8'],
    'public ipv6' => ['2001:4860:4860::8888'],
    'mapped public' => ['::ffff:8.8.8.8'],
]);
