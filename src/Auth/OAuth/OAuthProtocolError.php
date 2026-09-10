<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

use Infocyph\Epicrypt\Auth\Internal\AuthProtocolPolicy;
use Infocyph\Epicrypt\Exception\ConfigurationException;

final readonly class OAuthProtocolError
{
    public function __construct(
        public OAuthErrorCode $code,
        public ?string $redirectUri = null,
        public ?string $state = null,
    ) {
        if ($this->redirectUri !== null) {
            AuthProtocolPolicy::assertText(
                $this->redirectUri,
                AuthProtocolPolicy::MAX_REDIRECT_URI_BYTES,
                'OAuth error redirect URI',
            );
        }
        if ($this->state !== null
            && ($this->state === '' || !AuthProtocolPolicy::validParameterValue($this->state))) {
            throw new ConfigurationException('OAuth error state is invalid.');
        }
    }

    public function mayRedirect(): bool
    {
        return $this->redirectUri !== null;
    }

    /** @return array<string, string> */
    public function responseParameters(?string $issuer = null): array
    {
        if ($this->mayRedirect() && $issuer === null) {
            throw new ConfigurationException('Redirectable OAuth authorization errors require issuer identification.');
        }
        if ($issuer !== null) {
            AuthProtocolPolicy::assertText($issuer, AuthProtocolPolicy::MAX_ISSUER_BYTES, 'OAuth response issuer');
        }

        return [
            'error' => $this->code->value,
            ...($issuer === null ? [] : ['iss' => $issuer]),
            ...($this->state === null ? [] : ['state' => $this->state]),
        ];
    }
}
