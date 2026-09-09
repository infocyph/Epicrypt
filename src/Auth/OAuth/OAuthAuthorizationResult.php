<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use LogicException;

final readonly class OAuthAuthorizationResult
{
    private function __construct(
        public ?OAuthAuthorizationRequest $request,
        public ?OAuthClient $client,
        public ?OAuthProtocolError $error,
    ) {}

    public static function accepted(OAuthAuthorizationRequest $request, OAuthClient $client): self
    {
        return new self($request, $client, null);
    }

    public static function rejected(OAuthProtocolError $error): self
    {
        return new self(null, null, $error);
    }

    public function acceptedRequest(): OAuthAuthorizationRequest
    {
        if ($this->request === null) {
            throw new LogicException('OAuth authorization result does not contain an accepted request.');
        }

        return $this->request;
    }
}
