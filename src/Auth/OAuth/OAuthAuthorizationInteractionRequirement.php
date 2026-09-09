<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\OAuth;

enum OAuthAuthorizationInteractionRequirement: string
{
    case SUBJECT_AUTHENTICATION = 'subject_authentication';
    case AUTHORIZATION_DECISION = 'authorization_decision';
}
