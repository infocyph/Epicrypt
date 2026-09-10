<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

use Infocyph\Epicrypt\Auth\OAuth\OAuthAuthorizationRequest;
use Infocyph\Epicrypt\Auth\OAuth\OAuthClient;
use Infocyph\Epicrypt\Auth\OAuth\OAuthProtocolError;
use LogicException;

final readonly class OpenIdAuthorizationResult
{
    private function __construct(
        public ?OAuthAuthorizationRequest $oauthRequest,
        public ?OAuthClient $client,
        public ?OpenIdAuthorizationRequest $openIdRequest,
        public ?OAuthProtocolError $error,
    ) {}

    public static function oauth(OAuthAuthorizationRequest $request, OAuthClient $client): self
    {
        return new self($request, $client, null, null);
    }

    public static function openId(OpenIdAuthorizationRequest $request, OAuthClient $client): self
    {
        return new self($request->oauth, $client, $request, null);
    }

    public static function rejected(OAuthProtocolError $error): self
    {
        return new self(null, null, null, $error);
    }

    public function accepted(): bool
    {
        return $this->oauthRequest !== null;
    }

    public function isOpenId(): bool
    {
        return $this->openIdRequest !== null;
    }

    public function requireOpenId(): OpenIdAuthorizationRequest
    {
        return $this->openIdRequest
            ?? throw new LogicException('Authorization result does not contain an OpenID Connect request.');
    }
}
