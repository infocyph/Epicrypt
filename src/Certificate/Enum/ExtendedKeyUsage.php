<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Certificate\Enum;

enum ExtendedKeyUsage: string
{
    case CLIENT_AUTH = 'clientAuth';

    case CODE_SIGNING = 'codeSigning';

    case EMAIL_PROTECTION = 'emailProtection';

    case SERVER_AUTH = 'serverAuth';

    case TIME_STAMPING = 'timeStamping';
}
