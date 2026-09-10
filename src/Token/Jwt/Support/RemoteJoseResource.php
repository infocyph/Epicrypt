<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Infocyph\Epicrypt\Token\Jwt\RemoteJoseHostResolverInterface;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Throwable;

/** @internal Bounded PSR-18 JSON resource boundary. */
final readonly class RemoteJoseResource
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
        private int $maximumBytes,
        private int $maximumKeys,
        private RemoteJoseHostResolverInterface $hostResolver,
    ) {}

    /** @return array{array<string, mixed>, array{maxAge: int|null, noStore: bool, noCache: bool}} */
    public function fetch(string $uri, bool $jwks = false): array
    {
        $this->assertPublicTarget($uri);

        try {
            $request = $this->requestFactory->createRequest('GET', $uri)
                ->withHeader('Accept', $jwks ? 'application/jwk-set+json, application/json' : 'application/json');
            $response = $this->client->sendRequest($request);
        } catch (ClientExceptionInterface $exception) {
            throw new KeyResolutionException('Remote JOSE request failed.', 0, $exception);
        }
        if ($response->getStatusCode() !== 200) {
            throw new KeyResolutionException(sprintf('Remote JOSE endpoint returned HTTP %d.', $response->getStatusCode()));
        }
        $contentType = strtolower(trim(explode(';', $response->getHeaderLine('Content-Type'), 2)[0]));
        $allowedMediaTypes = $jwks ? ['application/jwk-set+json', 'application/json'] : ['application/json'];
        if (!in_array($contentType, $allowedMediaTypes, true)) {
            throw new KeyResolutionException('Remote JOSE endpoint returned a non-JSON content type.');
        }
        $body = $response->getBody();
        if (($size = $body->getSize()) !== null && $size > $this->maximumBytes) {
            throw new KeyResolutionException('Remote JOSE response exceeds the configured size bound.');
        }
        $json = '';
        while (!$body->eof()) {
            $json .= $body->read(min(8192, ($this->maximumBytes + 1) - strlen($json)));
            if (strlen($json) > $this->maximumBytes) {
                throw new KeyResolutionException('Remote JOSE response exceeds the configured size bound.');
            }
        }

        $maximumMembers = $jwks
            ? 1 + ($this->maximumKeys * (JosePolicy::MAX_JWK_MEMBERS + 1))
            : JosePolicy::MAX_DOCUMENT_MEMBERS;

        return [
            JwtToken::decodeJsonObject($json, 'remote JOSE document', $this->maximumBytes, $maximumMembers),
            $this->cachePolicy($response->getHeaderLine('Cache-Control')),
        ];
    }

    private function assertPublicTarget(string $uri): void
    {
        $host = parse_url($uri, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            throw new KeyResolutionException('Remote JOSE target host is invalid.');
        }
        $host = strtolower(trim($host, '[]'));

        try {
            $addresses = filter_var($host, FILTER_VALIDATE_IP) !== false
                ? [$host]
                : $this->hostResolver->resolve($host);
        } catch (Throwable $exception) {
            throw new KeyResolutionException('Remote JOSE host resolution failed.', 0, $exception);
        }

        if ($addresses === []) {
            throw new KeyResolutionException('Remote JOSE host did not resolve to an allowed address.');
        }
        foreach ($addresses as $address) {
            if (!$this->isPublicAddress($address)) {
                throw new KeyResolutionException('Remote JOSE host resolved to a disallowed address.');
            }
        }
    }

    /** @return array{maxAge: int|null, noStore: bool, noCache: bool} */
    private function cachePolicy(string $cacheControl): array
    {
        $maxAge = preg_match('/(?:^|,)\s*max-age\s*=\s*(\d+)/i', $cacheControl, $matches) === 1
            ? (filter_var($matches[1], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0]]) ?: 0)
            : null;

        return [
            'maxAge' => $maxAge,
            'noStore' => preg_match('/(?:^|,)\s*no-store(?:\s*(?:,|$))/i', $cacheControl) === 1,
            'noCache' => preg_match('/(?:^|,)\s*no-cache(?:\s*(?:,|$))/i', $cacheControl) === 1,
        ];
    }

    private function isPublicAddress(string $address): bool
    {
        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $packed = inet_pton($address);
        if (is_string($packed)
            && strlen($packed) === 16
            && substr($packed, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $mapped = inet_ntop(substr($packed, 12, 4));

            return is_string($mapped) && $this->isPublicAddress($mapped);
        }

        return filter_var(
            $address,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE,
        ) !== false;
    }
}
