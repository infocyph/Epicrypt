<?php


namespace AbmmHasan\SafeGuard\Crypt;


use Exception;
use Generator;
use NoRewindIterator;
use SplFileObject;

class FileCrypt extends StringCrypt
{
    private int $blockSize = 1024;
    private SplFileObject $file;
    private string $outFilePath = '';

    /**
     * Set output file path
     *
     * @param string $pathToFile
     */
    public function setOutFile(string $pathToFile)
    {
        $this->outFilePath = realpath($pathToFile);
    }

    /**
     * Set block size
     *
     * @param $size
     */
    public function setBlockSize($size)
    {
        $this->blockSize = $size;
    }

    /**
     * Encrypt file content
     *
     * @param string $input Input file location (realpath compatible)
     * @return string
     * @throws Exception
     */
    public function encrypt(string $input): string
    {
        $this->setInfo('process', 'encryption');
        $this->setInfo('type', 'file');
        $input = realpath($input);
        if (!file_exists($input) || !is_readable($input)) {
            throw new Exception("Invalid input file path ($input)!");
        }
        $inputLocDetails = pathinfo($input);
        if (empty($this->outFilePath)) {
            $this->outFilePath = $inputLocDetails['dirname'] . DIRECTORY_SEPARATOR . $inputLocDetails['filename'] . '.bin';
        } else {
            $outFile = pathinfo($this->outFilePath);
            $this->outFilePath = ($outFile['dirname'] ?? $inputLocDetails['dirname']) .
                DIRECTORY_SEPARATOR .
                ($outFile['filename'] ?? $inputLocDetails['filename']) .
                ($outFile['extension'] ?? '.bin');
        }
        return $this->process($input, 'encrypt');
    }

    /**
     * Decrypt file content
     *
     * @param string $input
     * @return bool|int
     * @throws Exception
     */
    public function decrypt(string $input)
    {
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'file');
        $input = realpath($input);
        if (!file_exists($input) || !is_readable($input)) {
            throw new Exception("Invalid input file path ($input)!");
        }
        if (empty($this->outFilePath)) {
            $inputLocDetails = pathinfo($input);
            $this->outFilePath = $inputLocDetails['dirname'] . DIRECTORY_SEPARATOR . $inputLocDetails['filename'] . '.decompressed.txt';
        }
        return $this->process($input, 'decrypt');
    }

    /**
     * @param $input
     * @param $type
     * @return false|int
     * @throws Exception
     */
    private function process($input, $type)
    {
        if (empty($this->outFilePath) || file_put_contents($this->outFilePath, '') === false) {
            throw new Exception('Invalid output file path!');
        }
        $this->file = new SplFileObject($input, 'rb');
        $writeBytes = $readBytes = 0;
        $readChunkSize = $writeChunkSize = [];
        foreach (new NoRewindIterator($this->iterate()) as $chunk) {
            $readBytes += $readChunkSize[] = mb_strlen($chunk, '8bit');
            $writeBytes += $writeChunkSize[] = file_put_contents($this->outFilePath, parent::$type($chunk), FILE_APPEND | LOCK_EX);
        }
        $this->setInfo('pieces', count(array_filter($writeChunkSize)));
        $this->setInfo('writeBlockSize', $writeChunkSize[0]);
        $this->setInfo('readBlockSize', $readChunkSize[0]);
        $this->setInfo('bytesWritten', $writeBytes);
        $this->setInfo('bytesRead', $readBytes);
        return $writeBytes;
    }

    /**
     * @return Generator
     */
    private function iterate(): Generator
    {
        $count = 0;
        while (!$this->file->eof()) {
            yield $this->file->fread($this->blockSize);
            $count++;
        }
    }
}
