<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Exception\Token\InvalidTokenException;

final readonly class OAuthResourceAccessTokenValidator
{
    public function __construct(
        private OAuthAccessTokenService $accessTokens,
        private ?OAuthDpopValidator $dpop = null,
    ) {}

    public function validate(
        #[\SensitiveParameter]
        string $accessToken,
        string $audience,
        string $method,
        string $uri,
        #[\SensitiveParameter]
        ?string $dpopProof = null,
    ): OAuthResourceAccessTokenResult {
        $validation = $this->accessTokens->validate($accessToken, $audience);
        if (!$validation->valid()) {
            return OAuthResourceAccessTokenResult::failure(OAuthResourceAccessTokenStatus::INVALID_TOKEN, $validation);
        }

        $jkt = $validation->claims['cnf']['jkt'] ?? null;
        if (!is_string($jkt)) {
            return OAuthResourceAccessTokenResult::success($validation);
        }
        if ($dpopProof === null || $this->dpop === null) {
            return OAuthResourceAccessTokenResult::failure(OAuthResourceAccessTokenStatus::DPOP_REQUIRED, $validation);
        }

        try {
            $context = $this->dpop->validateResourceRequest(
                $dpopProof,
                $accessToken,
                $validation->claims,
                $method,
                $uri,
            );
        } catch (InvalidTokenException) {
            return OAuthResourceAccessTokenResult::failure(OAuthResourceAccessTokenStatus::INVALID_DPOP_PROOF, $validation);
        }

        return OAuthResourceAccessTokenResult::success($validation, $context);
    }
}
