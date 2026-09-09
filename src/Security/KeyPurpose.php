<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Security;

enum KeyPurpose
{
    case DATA_PROTECTION;

    case ENVELOPE_PROTECTION;

    case FILE_PROTECTION;

    case JWT_SIGNING;

    case KEY_ROTATION;

    case SECRET_WRAPPING;

    case SIGNED_PAYLOAD;

    case SIGNED_URL;

    case OAUTH_ACCESS_TOKEN_SIGNING;

    case OAUTH_AUTHORIZATION_CODE_PROTECTION;

    case OAUTH_REFRESH_TOKEN_PROTECTION;

    case OIDC_ID_TOKEN_SIGNING;

    case OIDC_ID_TOKEN_ENCRYPTION;

    case API_PERSONAL_TOKEN_SIGNING;
}
