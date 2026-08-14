<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Jwt\Support;

use Infocyph\Epicrypt\Exception\Token\KeyResolutionException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/** @internal Bounded PSR-18 JSON resource boundary. */
final readonly class RemoteJoseResource
{
    public function __construct(
        private ClientInterface $client,
        private RequestFactoryInterface $requestFactory,
        private int $maximumBytes,
    ) {}

    /** @return array{array<string, mixed>, array{maxAge: int|null, noStore: bool, noCache: bool}} */
    public function fetch(string $uri, bool $jwks = false): array
    {
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
        $this->assertJsonDepth($json, 16);

        return [JwtToken::decodeJsonObject($json, 'remote JOSE document'), $this->cachePolicy($response->getHeaderLine('Cache-Control'))];
    }

    private function assertJsonDepth(string $json, int $maximum): void
    {
        $depth = 0;
        for ($offset = 0, $length = strlen($json); $offset < $length; $offset++) {
            $character = $json[$offset];
            if ($character === '"') {
                $offset = $this->stringEnd($json, $offset + 1);

                continue;
            }
            if ($character === '{' || $character === '[') {
                if (++$depth > $maximum) {
                    throw new KeyResolutionException('Remote JOSE JSON exceeds the configured depth bound.');
                }
            } elseif ($character === '}' || $character === ']') {
                $depth--;
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

    private function stringEnd(string $json, int $offset): int
    {
        for ($length = strlen($json); $offset < $length; $offset++) {
            if ($json[$offset] === '\\') {
                $offset++;
            } elseif ($json[$offset] === '"') {
                return $offset;
            }
        }

        throw new KeyResolutionException('Remote JOSE JSON contains an unterminated string.');
    }
}
