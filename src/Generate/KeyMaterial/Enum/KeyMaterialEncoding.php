<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Generate\KeyMaterial\Enum;

enum KeyMaterialEncoding
{
    case BASE64URL;

    case HEX;

    case RAW;
}
