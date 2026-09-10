<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAuthorizationInteractionRequirement: string
{
    case AUTHORIZATION_DECISION = 'authorization_decision';

    case SUBJECT_AUTHENTICATION = 'subject_authentication';
}
