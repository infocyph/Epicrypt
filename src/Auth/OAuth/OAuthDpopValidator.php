<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Token\Jwt\DpopProof;
use Infocyph\Epicrypt\Token\Jwt\Enum\AsymmetricJwtAlgorithm;
use Infocyph\Epicrypt\Token\Jwt\JwtReplayStoreInterface;

final readonly class OAuthDpopValidator
{
    public function __construct(
        private JwtReplayStoreInterface $replayStore,
        public AsymmetricJwtAlgorithm $algorithm = AsymmetricJwtAlgorithm::ES256,
        private DpopProof $proof = new DpopProof(),
    ) {}

    /** @param array<string, mixed> $accessTokenClaims */
    public function validateResourceRequest(
        #[\SensitiveParameter]
        string $proof,
        #[\SensitiveParameter]
        string $accessToken,
        array $accessTokenClaims,
        string $method,
        string $uri,
    ): OAuthDpopContext {
        $verified = $this->proof->verifyResult(
            $proof,
            $method,
            $uri,
            $this->algorithm,
            $this->replayStore,
            accessToken: $accessToken,
        );
        $this->proof->validateAccessTokenBinding($accessTokenClaims, $verified['publicJwk']);

        return new OAuthDpopContext($verified['keyThumbprint'], $verified['publicJwk']);
    }

    public function validateTokenEndpoint(
        #[\SensitiveParameter]
        string $proof,
        string $tokenEndpointUri,
    ): OAuthDpopContext {
        $verified = $this->proof->verifyResult(
            $proof,
            'POST',
            $tokenEndpointUri,
            $this->algorithm,
            $this->replayStore,
        );

        return new OAuthDpopContext($verified['keyThumbprint'], $verified['publicJwk']);
    }
}
