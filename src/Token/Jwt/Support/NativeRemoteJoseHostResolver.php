<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;

/** @internal */
final class NativeRemoteJoseHostResolver implements RemoteJoseHostResolverInterface
{
    public function resolve(string $hostname): array
    {
        if (filter_var($hostname, FILTER_VALIDATE_IP) !== false) {
            return [$hostname];
        }

        $records = dns_get_record($hostname, DNS_A | DNS_AAAA);
        if (!is_array($records)) {
            return [];
        }

        $addresses = [];
        foreach ($records as $record) {
            $address = $record['ip'] ?? $record['ipv6'] ?? null;
            if (is_string($address) && filter_var($address, FILTER_VALIDATE_IP) !== false) {
                $addresses[] = $address;
            }
        }

        $addresses = array_values(array_unique($addresses));
        sort($addresses, SORT_STRING);

        return $addresses;
    }
}
