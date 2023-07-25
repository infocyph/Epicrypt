<?php

namespace AbmmHasan\SafeGuard\Misc;

use Exception;
use Generator;
use NoRewindIterator;
use SplFileObject;

/**
 * Memory-safe file reader
 *
 * @method ReadFile character() Get character iterator
 * @method ReadFile line() Get line iterator
 * @method ReadFile csv(string $separator = ",", string $enclosure = "\"", string $escape = "\\") Get line iterator parsed as CSV
 * @method ReadFile binary(int $bytes = 1024) Get binary iterator
 */
final class ReadFile
{
    private SplFileObject $file;
    public int $count = 0;

    /**
     * @param string $filename
     * @param string $mode
     * @throws Exception
     */
    public function __construct(private string $filename, private string $mode = "r")
    {
    }

    /**
     * Get iterator
     *
     * @param $type
     * @param $params
     * @return NoRewindIterator
     * @throws Exception
     */
    public function __call($type, $params)
    {
        $this->initiate();
        return new NoRewindIterator(
            match (strtolower($type)) {
                'character' => $this->characterIterator(),
                'line' => $this->lineIterator(),
                'csv' => $this->csvIterator(...$params),
                'binary' => $this->binaryIterator(...$params),
                default => throw new Exception("Unknown iterator type($type)!")
            }
        );
    }

    /**
     * @param $property
     * @param mixed ...$params
     * @return mixed
     * @throws Exception
     */
    public function set($property, ...$params): mixed
    {
        $this->initiate();
        return $this->file->$property(...$params);
    }

    /**
     * SplFileObject initiator
     *
     * @throws Exception
     */
    private function initiate()
    {
        if (!isset($this->file)) {
            if (!file_exists($this->filename) || !is_readable($this->filename)) {
                throw new Exception("Invalid file path!");
            }
            $this->file = new SplFileObject($this->filename, $this->mode);
        }
    }

    /**
     * @return Generator
     */
    private function characterIterator(): Generator
    {
        while (!$this->file->eof()) {
            yield $this->file->fgetc();
            $this->count++;
        }
    }

    /**
     * @return Generator
     */
    private function lineIterator(): Generator
    {
        while (!$this->file->eof()) {
            yield $this->file->fgets();
            $this->count++;
        }
    }

    /**
     * @param string $separator
     * @param string $enclosure
     * @param string $escape
     * @return Generator
     */
    private function csvIterator(string $separator = ",", string $enclosure = "\"", string $escape = "\\"): Generator
    {
        while (!$this->file->eof()) {
            yield $this->file->fgetcsv($separator, $enclosure, $escape);
            $this->count++;
        }
    }

    /**
     * @param int $bytes
     * @return Generator
     */
    private function binaryIterator(int $bytes = 1024): Generator
    {
        while (!$this->file->eof()) {
            yield $this->file->fread($bytes);
            $this->count++;
        }
    }
}
