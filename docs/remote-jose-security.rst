Remote JOSE security
====================

``RemoteJwks`` retrieves OpenID discovery metadata and JWKS only from trusted
application configuration. It never follows ``jku`` or ``x5u`` supplied by an
untrusted token.

Destination policy
------------------

``RemoteJwksConfiguration`` is HTTPS-only by default. URLs containing
credentials or fragments are rejected. Literal private, loopback, link-local
and reserved IPv4/IPv6 destinations are rejected. A JWKS host must equal the
configured issuer host unless the application explicitly lists the DNS hostname
in ``allowedJwksHosts``.

Immediately before every outbound discovery or JWKS request, Epicrypt resolves
the destination hostname and rejects the request unless every returned address
is a syntactically valid public IP address. Empty answers, malformed answers,
private/reserved addresses, IPv4-mapped private IPv6 addresses, and mixed
public/private answer sets all fail closed. A later refresh resolves the host
again; a previous public answer is never treated as authority for a future
request.

The default resolver uses native A and AAAA DNS lookup. Applications with a
network-aware HTTP stack may inject ``RemoteJoseHostResolverInterface`` so the
validation resolver can be coupled to the transport's own resolver or pinning
policy.

.. code-block:: php

   <?php

   declare(strict_types=1);

   use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;
   use Infocyph\Epicrypt\Token\Jwt\RemoteJwks;
   use Infocyph\Epicrypt\Token\Jwt\RemoteJwksConfiguration;

   final class ApplicationJoseResolver implements RemoteJoseHostResolverInterface
   {
       public function resolve(string $hostname): array
       {
           // Resolve through the same controlled network policy used by the
           // application's HTTP transport and return only concrete IP strings.
           return $this->networkPolicy->resolvePublicAddresses($hostname);
       }
   }

   $remote = new RemoteJwks(
       $psr18Client,
       $psr17RequestFactory,
       new RemoteJwksConfiguration('https://issuer.example'),
       $psr16Cache,
       hostResolver: new ApplicationJoseResolver(),
   );

PSR-18 transport boundary
-------------------------

PSR-18 does not expose the socket's connected IP address and does not standardize
automatic redirect behavior. Epicrypt therefore cannot truthfully guarantee
transport-level DNS pinning through an arbitrary PSR-18 client.

For production deployments:

- disable automatic redirects in the supplied HTTP client;
- treat visible 3xx responses as failures (Epicrypt already rejects non-200
  responses);
- configure short connect and overall/read timeouts in the HTTP client;
- when DNS-rebinding resistance must include the connected socket, use a client
  whose resolver/pinning controls can be coupled to the injected
  ``RemoteJoseHostResolverInterface``;
- do not configure a proxy or custom transport that can silently reinterpret the
  validated destination unless that path enforces equivalent public-address
  policy.

Response and parser bounds
--------------------------

Remote responses are streamed through a configured byte ceiling before JSON is
accepted. JOSE JSON also has a bounded nesting depth and member count. JWKS has
a configured maximum key count plus a per-JWK structural member ceiling. These
bounds are applied before key import or signature work.

Discovery must return the exact configured issuer. JWKS accepts only
``application/jwk-set+json`` or ``application/json``; discovery accepts only
``application/json``.

Caching and failure behavior
----------------------------

``Cache-Control: no-store`` prevents persistence. ``no-cache`` forces network
revalidation. ``max-age`` is clamped to the configured minimum/maximum TTL.
Cached JWKS values are structurally revalidated before use; malformed or
oversized cached values are ignored and refreshed.

A bounded stale value may be used only after an ordinary refresh failure while
its configured stale window is still active. An explicit/forced refresh never
falls back to stale data. Unknown ``kid`` resolution performs at most one forced
refresh.

The cache key is derived from both the configured issuer and the configured
JWKS/discovery mode, preventing unrelated issuer configurations from sharing a
cache entry.
