<?php

namespace AbmmHasan\SafeGuard\Symmetric\OpenSSL;

use AbmmHasan\SafeGuard\Misc\ReadFile;
use Exception;

class FileCrypt
{
    use SSLCommon;

    private int $blockSize;
    private string $outFilePath = '';
    private array $tags = [];

    /**
     * Set output file path
     *
     * @param string $pathToFile
     */
    public function setOutFile(string $pathToFile)
    {
        $this->outFilePath = $pathToFile;
    }

    /**
     * Set Tag(s) for GCM/CCM mode
     *
     * @param array $tags
     */
    public function setTags(array $tags)
    {
        $this->tags = $tags;
    }

    /**
     * Encrypt file content
     *
     * @param string $input Input file location (realpath compatible)
     * @param int $blockSize Set read block size (in bytes)
     * @return string Write block size (in bytes)
     * @throws Exception
     */
    public function encrypt(string $input, int $blockSize = 1024): string
    {
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'file');
        $this->blockSize = $blockSize;
        $input = realpath($input);
        if (!file_exists($input) || !is_readable($input)) {
            throw new Exception("Invalid input file path ($input)!");
        }
        $inputLocDetails = pathinfo($input);
        if (empty($this->outFilePath)) {
            $this->outFilePath = $inputLocDetails['dirname'] . DIRECTORY_SEPARATOR .
                $inputLocDetails['filename'] . '.bin';
        } else {
            $outFile = pathinfo($this->outFilePath);
            $this->outFilePath = ($outFile['dirname'] ?? $inputLocDetails['dirname']) .
                DIRECTORY_SEPARATOR . ($outFile['filename'] ?? $inputLocDetails['filename']) .
                '.' . ($outFile['extension'] ?? 'bin');
        }
        $this->setInfo('inFile', $input);
        $this->setInfo('outFile', $this->outFilePath);
        return $this->process($input, 'encryptionProcess');
    }

    /**
     * Decrypt file content
     *
     * @param string $input Input file location (realpath compatible)
     * @param int $blockSize Set read block size (retrieved write block size during encryption)
     * @return string
     * @throws Exception
     */
    public function decrypt(string $input, int $blockSize): string
    {
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'file');
        $this->blockSize = $blockSize;
        $input = realpath($input);
        if (!file_exists($input) || !is_readable($input)) {
            throw new Exception("Invalid input file path ($input)!");
        }
        $inputLocDetails = pathinfo($input);
        if (empty($this->outFilePath)) {
            $this->outFilePath = $inputLocDetails['dirname'] . DIRECTORY_SEPARATOR .
                $inputLocDetails['filename'] . '.decompressed';
        } else {
            $outFile = pathinfo($this->outFilePath);
            $this->outFilePath = ($outFile['dirname'] ?? $inputLocDetails['dirname']) .
                DIRECTORY_SEPARATOR . ($outFile['filename'] ?? $inputLocDetails['filename']) .
                '.' . ($outFile['extension'] ?? 'decompressed');
        }
        $this->setInfo('inFile', $input);
        $this->setInfo('outFile', $this->outFilePath);
        return $this->process($input, 'decryptionProcess');
    }

    /**
     * Content processor
     *
     * @param $input
     * @param $type
     * @return float|int
     * @throws Exception
     */
    private function process($input, $type): float|int
    {
        if (empty($this->outFilePath) || file_put_contents($this->outFilePath, '') === false) {
            throw new Exception('Invalid output file path!');
        }
        $this->disableSignatureForGcmCcm();
        $writeChunkSize = [];
        $fileObject = new ReadFile($input, 'rb');
        foreach ($fileObject->binary($this->blockSize) as $index => $chunk) {
            $this->tag = $this->tags[$index] ?? '';
            $writeChunkSize[] = file_put_contents($this->outFilePath, self::$type($chunk), FILE_APPEND | LOCK_EX);
        }
        $this->setInfo('pieces', count(array_filter($writeChunkSize)));
        $this->setInfo('bytesWritten', array_sum($writeChunkSize));
        return $this->setInfo('writeBlockSize', current($writeChunkSize));
    }
}
