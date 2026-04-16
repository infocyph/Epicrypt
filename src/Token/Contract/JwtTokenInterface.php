<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Contract;

interface JwtTokenInterface extends TokenEncoderInterface, TokenDecoderInterface, TokenVerifierInterface {}
