<?php

declare(strict_types=1);

use Infocyph\Epicrypt\Auth\OAuth\OAuthClientAuthenticationMethod;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapability;
use Infocyph\Epicrypt\Auth\OAuth\OAuthEndpointCapabilityCatalog;
use Infocyph\Epicrypt\Auth\OAuth\OAuthGrantType;

it('reports only explicitly composed endpoint capabilities without routes', function () {
    $catalog = new OAuthEndpointCapabilityCatalog(
        endpoints: [OAuthEndpointCapability::AUTHORIZATION],
        grantTypes: [OAuthGrantType::AUTHORIZATION_CODE],
        clientAuthenticationMethods: [OAuthClientAuthenticationMethod::NONE],
    );

    expect($catalog->supportsEndpoint(OAuthEndpointCapability::AUTHORIZATION))->toBeTrue()
        ->and($catalog->supportsEndpoint(OAuthEndpointCapability::TOKEN))->toBeFalse()
        ->and($catalog->responseTypes())->toBe(['code'])
        ->and($catalog->codeChallengeMethods())->toBe(['S256']);
});
