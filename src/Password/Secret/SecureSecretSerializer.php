<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Password\Secret;

use Infocyph\Epicrypt\Internal\Json;

final class SecureSecretSerializer
{
    /**
     * @return array<string, mixed>
     */
    public function deserialize(#[\SensitiveParameter] string $serialized): array
    {
        return Json::decodeToArray($serialized);
    }

    /**
     * @param array<string, scalar|array<string, scalar>> $secret
     */
    public function serialize(#[\SensitiveParameter] array $secret): string
    {
        return Json::encode($secret);
    }
}
