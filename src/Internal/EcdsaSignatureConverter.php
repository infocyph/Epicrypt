<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Internal;

use Infocyph\Epicrypt\Exception\Token\SignatureEncodingException;

final class EcdsaSignatureConverter
{
    private string $asn1BigIntLimit = '7f';

    private string $asn1Int = '02';

    private string $asn1Length2Byte = '81';

    private int $asn1MaxSingleByte = 128;

    private string $asn1NegativeInteger = '00';

    private string $asn1Seq = '30';

    private int $byteSize = 2;

    /**
     * Convert ASN1 string to JOSE signature.
     *
     * @throws SignatureEncodingException
     */
    public function fromAsn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;

        if ($this->asn1Seq !== $this->readAsn1Content($message, $position, $this->byteSize)) {
            throw new SignatureEncodingException('Invalid data. Should start with a sequence.');
        }

        if ($this->asn1Length2Byte === $this->readAsn1Content($message, $position, $this->byteSize)) {
            $position += $this->byteSize;
        }

        $pointR = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));
        $pointS = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));

        $bin = hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT) . str_pad($pointS, $length, '0', STR_PAD_LEFT));
        if (!is_string($bin)) {
            throw new SignatureEncodingException('Unable to parse the data.');
        }

        return $bin;
    }

    /**
     * Convert JOSE signature to ASN1 string.
     *
     * @throws SignatureEncodingException
     */
    public function toAsn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);

        if ($this->octetLength($signature) !== $length) {
            throw new SignatureEncodingException('Invalid signature length.');
        }

        $pointR = $this->preparePositiveInteger(substr($signature, 0, $length));
        $pointS = $this->preparePositiveInteger(substr($signature, $length));

        $lengthR = $this->octetLength($pointR);
        $lengthS = $this->octetLength($pointS);
        $totalLength = $lengthR + $lengthS + $this->byteSize + $this->byteSize;
        $lengthPrefix = $totalLength > $this->asn1MaxSingleByte ? $this->asn1Length2Byte : '';

        $bin = hex2bin(
            $this->asn1Seq
            . $lengthPrefix . dechex($totalLength)
            . $this->asn1Int . dechex($lengthR) . $pointR
            . $this->asn1Int . dechex($lengthS) . $pointS,
        );

        if (!is_string($bin)) {
            throw new SignatureEncodingException('Data parsing failed.');
        }

        return $bin;
    }

    private function octetLength(string $data): int
    {
        return (int) (strlen($data) / $this->byteSize);
    }

    private function preparePositiveInteger(string $data): string
    {
        if (substr($data, 0, $this->byteSize) > $this->asn1BigIntLimit) {
            return $this->asn1NegativeInteger . $data;
        }

        while (str_starts_with($data, $this->asn1NegativeInteger)
            && substr($data, 2, $this->byteSize) <= $this->asn1BigIntLimit) {
            $data = substr($data, 2);
        }

        return $data;
    }

    private function readAsn1Content(string $message, int &$position, int $length): string
    {
        $content = substr($message, $position, $length);
        $position += $length;

        return $content;
    }

    /**
     * @throws SignatureEncodingException
     */
    private function readAsn1Integer(string $message, int &$position): string
    {
        if ($this->asn1Int !== $this->readAsn1Content($message, $position, $this->byteSize)) {
            throw new SignatureEncodingException('Invalid data. Should contain an integer.');
        }

        $length = (int) hexdec($this->readAsn1Content($message, $position, $this->byteSize));

        return $this->readAsn1Content($message, $position, $length * $this->byteSize);
    }

    private function retrievePositiveInteger(string $data): string
    {
        while (str_starts_with($data, $this->asn1NegativeInteger)
            && substr($data, 2, $this->byteSize) > $this->asn1BigIntLimit) {
            $data = substr($data, 2);
        }

        return $data;
    }
}
