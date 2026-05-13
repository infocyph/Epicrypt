<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Token\Contract;

interface PayloadTokenInterface extends TokenDecoderInterface, TokenEncoderInterface, TokenVerifierInterface {}
