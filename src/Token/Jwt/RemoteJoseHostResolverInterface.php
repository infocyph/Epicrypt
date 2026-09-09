<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt;

interface RemoteJoseHostResolverInterface
{
    /**
     * Resolve a DNS hostname to the IP addresses that may be used for one
     * outbound Remote JOSE request.
     *
     * Implementations must not return hostnames or silently substitute a
     * different destination. Returning an empty list fails the request closed.
     *
     * @return list<string>
     */
    public function resolve(string $hostname): array;
}
