<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Auth\Oidc;

enum OpenIdInteractionErrorCode: string
{
    case ACCOUNT_SELECTION_REQUIRED = 'account_selection_required';

    case CONSENT_REQUIRED = 'consent_required';

    case INTERACTION_REQUIRED = 'interaction_required';

    case LOGIN_REQUIRED = 'login_required';
}
