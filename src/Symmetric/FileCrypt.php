<?php


namespace AbmmHasan\SafeGuard\Symmetric;


use Exception;
use Generator;
use NoRewindIterator;
use SplFileObject;

class FileCrypt
{
    use Common;

    private int $blockSize = 1024;
    private SplFileObject $file;
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
     * Set block size
     *
     * @param $size
     */
    public function setReadBlockSize($size)
    {
        $this->blockSize = $size;
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
     * @return string
     * @throws Exception
     */
    public function decrypt(string $input): string
    {
        $this->setInfo('process', 'decryption');
        $this->setInfo('type', 'file');
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
        $this->file = new SplFileObject($input, 'rb');
        $readChunkSize = $writeChunkSize = [];
        foreach (new NoRewindIterator($this->iterate()) as $index => $chunk) {
            $readChunkSize[] = mb_strlen($chunk, '8bit');
            $this->tag = $this->tags[$index] ?? '';
            $writeChunkSize[] = file_put_contents($this->outFilePath, self::$type($chunk), FILE_APPEND | LOCK_EX);
        }
        $this->setInfo('pieces', count(array_filter($writeChunkSize)));
        $this->setInfo('bytesRead', array_sum($readChunkSize));
        $this->setInfo('bytesWritten', array_sum($writeChunkSize));
        $this->setInfo('readBlockSize', $readChunkSize[0]);
        return $this->setInfo('writeBlockSize', $writeChunkSize[0]);
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
