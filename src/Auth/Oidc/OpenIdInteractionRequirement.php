<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdInteractionRequirement: string
{
    case SUBJECT_AUTHENTICATION = 'subject_authentication';
    case ACCOUNT_SELECTION = 'account_selection';
    case AUTHORIZATION_DECISION = 'authorization_decision';
    case READY = 'ready';
}
