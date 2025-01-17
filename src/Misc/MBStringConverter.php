<?php

declare(strict_types=1);

namespace Infocyph\Epicrypt\Misc;

use Exception;

final class MBStringConverter
{
    private string $asn1Seq = '30';
    private string $asn1Int = '02';
    private int $asn1MaxSingleByte = 128;
    private string $asn1Length2Byte = '81';
    private string $asn1BigIntLimit = '7f';
    private string $asn1NegativeInteger = '00';
    private int $byteSize = 2;

    /**
     * Convert MB String to ASN1 String
     *
     * @param string $signature
     * @param int $length
     * @return string
     * @throws Exception
     */
    public function toAsn1(string $signature, int $length): string
    {
        $signature = bin2hex($signature);

        if ($this->octetLength($signature) !== $length) {
            throw new Exception('Invalid signature length.');
        }

        $pointR = $this->preparePositiveInteger(mb_substr($signature, 0, $length, '8bit'));
        $pointS = $this->preparePositiveInteger(mb_substr($signature, $length, null, '8bit'));

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
            throw new Exception('Data parsing failed!');
        }

        return $bin;
    }

    /**
     * Convert ASN1 String to MB String
     *
     * @param string $signature
     * @param int $length
     * @return string
     * @throws Exception
     */
    public function fromAsn1(string $signature, int $length): string
    {
        $message = bin2hex($signature);
        $position = 0;

        if ($this->asn1Seq !== $this->readAsn1Content($message, $position, $this->byteSize)) {
            throw new Exception('Invalid data. Should start with a sequence.');
        }

        if ($this->asn1Length2Byte === $this->readAsn1Content($message, $position, $this->byteSize)) {
            $position += $this->byteSize;
        }

        $pointR = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));
        $pointS = $this->retrievePositiveInteger($this->readAsn1Integer($message, $position));

        $bin = hex2bin(str_pad($pointR, $length, '0', STR_PAD_LEFT) . str_pad($pointS, $length, '0', STR_PAD_LEFT));
        if (!is_string($bin)) {
            throw new Exception('Unable to parse the data');
        }

        return $bin;
    }

    private function octetLength(string $data): int
    {
        return (int) (mb_strlen($data, '8bit') / $this->byteSize);
    }

    private function preparePositiveInteger(string $data): string
    {
        if (mb_substr($data, 0, $this->byteSize, '8bit') > $this->asn1BigIntLimit) {
            return $this->asn1NegativeInteger . $data;
        }

        while (0 === mb_strpos($data, $this->asn1NegativeInteger, 0, '8bit')
            && mb_substr($data, 2, $this->byteSize, '8bit') <= $this->asn1BigIntLimit) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }

    private function readAsn1Content(string $message, int &$position, int $length): string
    {
        $content = mb_substr($message, $position, $length, '8bit');
        $position += $length;

        return $content;
    }

    /**
     * @throws Exception
     */
    private function readAsn1Integer(string $message, int &$position): string
    {
        if ($this->asn1Int !== $this->readAsn1Content($message, $position, $this->byteSize)) {
            throw new Exception('Invalid data. Should contain an integer.');
        }

        $length = (int) hexdec($this->readAsn1Content($message, $position, $this->byteSize));

        return $this->readAsn1Content($message, $position, $length * $this->byteSize);
    }

    private function retrievePositiveInteger(string $data): string
    {
        while (0 === mb_strpos($data, $this->asn1NegativeInteger, 0, '8bit')
            && mb_substr($data, 2, $this->byteSize, '8bit') > $this->asn1BigIntLimit) {
            $data = mb_substr($data, 2, null, '8bit');
        }

        return $data;
    }
}
