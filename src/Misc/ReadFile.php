<?php

namespace Infocyph\Epicrypt\Misc;

use Countable;
use Exception;
use Generator;
use Infocyph\Epicrypt\Exceptions\FileAccessException;
use Iterator;
use NoRewindIterator;
use SeekableIterator;
use SimpleXMLElement;
use SplFileObject;

/**
 * Memory-safe file reader with multiple read modes and interface support.
 *
 * @method ReadFile character() Character iterator
 * @method ReadFile line() Line iterator
 * @method ReadFile csv(string $separator = ",", string $enclosure = "\"", string $escape = "\\") CSV iterator
 * @method ReadFile binary(int $bytes = 1024) Binary iterator
 * @method ReadFile json() JSON line-by-line iterator
 * @method ReadFile regex(string $pattern) Regex iterator
 * @method ReadFile fixedWidth(array $widths) Fixed-width field iterator
 * @method ReadFile xml(string $element) XML iterator
 * @method ReadFile serialized() Serialized object iterator
 * @method ReadFile jsonArray() JSON array iterator
 */
final class ReadFile implements Countable, Iterator, SeekableIterator
{
    private SplFileObject $file;

    private int $count = 0;

    private int $position = 0;

    private ?Generator $currentIterator = null;

    /**
     * Constructor.
     *
     * @param  string  $filename  The file to read.
     * @param  string  $mode  The mode to open the file in. Default is 'r'.
     */
    public function __construct(private readonly string $filename, private readonly string $mode = 'r') {}

    /**
     * Magic method to handle various iterators.
     *
     * @param  string  $type  The type of iterator to call.
     * @param  array  $params  The parameters to pass to the iterator.
     * @return NoRewindIterator The iterator to use.
     *
     * @throws Exception If the iterator type is unknown.
     */
    public function __call(string $type, array $params): NoRewindIterator
    {
        $this->initiate();
        $this->currentIterator = match (strtolower($type)) {
            'character' => $this->characterIterator(),
            'line' => $this->lineIterator(),
            'csv' => $this->csvIterator(...$params),
            'binary' => $this->binaryIterator(...$params),
            'json' => $this->jsonIterator(),
            'regex' => $this->regexIterator(...$params),
            'fixedwidth' => $this->fixedWidthIterator(...$params),
            'xml' => $this->xmlIterator(...$params),
            'serialized' => $this->serializedIterator(),
            'jsonarray' => $this->jsonArrayIterator(),
            default => throw new Exception("Unknown iterator type '$type'"),
        };

        return new NoRewindIterator($this->currentIterator);
    }

    /**
     * Initializes the SplFileObject instance for the specified file.
     *
     * Checks if the file is accessible and readable, and creates an SplFileObject
     * for it if not already initialized. Resets the position counters upon initialization.
     *
     * @throws FileAccessException If the file cannot be accessed or read.
     */
    private function initiate(): void
    {
        if (! isset($this->file)) {
            if (! is_file($this->filename) || ! is_readable($this->filename)) {
                throw new FileAccessException("Cannot access file at path: $this->filename");
            }
            $this->file = new SplFileObject($this->filename, $this->mode);
            $this->resetPosition();
        }
    }

    /**
     * Iterator: Returns the current item.
     *
     * If the current iterator is null, returns null.
     *
     * @return mixed The current item in the iterator.
     */
    public function current(): mixed
    {
        return $this->currentIterator?->current();
    }

    /**
     * Iterator: Returns the current key (position).
     *
     * @return int The current position in the iterator.
     */
    public function key(): int
    {
        return $this->position;
    }

    /**
     * Iterator: Moves to the next item.
     *
     * Advances the current iterator to the next item and increments the position counter.
     */
    public function next(): void
    {
        if ($this->currentIterator) {
            $this->currentIterator->next();
            $this->position++;
        }
    }

    /**
     * Resets the iterator to the beginning of the file, rewinding the current iterator.
     */
    public function rewind(): void
    {
        $this->reset();
        if ($this->currentIterator) {
            $this->currentIterator->rewind();
        }
    }

    /**
     * Returns whether the current iterator position is valid.
     *
     * @return bool True if the current position is valid, false if it is not.
     */
    public function valid(): bool
    {
        return $this->currentIterator && $this->currentIterator->valid();
    }

    /**
     * Seeks to a given position in the file.
     *
     * @param  int  $offset  The position to seek to.
     *
     * @throws Exception If the position is negative.
     */
    public function seek(int $offset): void
    {
        if ($offset < 0) {
            throw new Exception("Invalid position ($offset)");
        }
        $this->rewind();
        while ($this->position < $offset && $this->valid()) {
            $this->next();
        }
    }

    /**
     * Returns the total number of items processed by the iterator.
     *
     * This method provides the current count of items that have been processed
     * or iterated over in the file.
     *
     * @return int The number of items processed.
     */
    public function count(): int
    {
        return $this->count;
    }

    /**
     * Resets the iterator to the beginning of the file.
     */
    public function reset(): void
    {
        $this->file->rewind();
        $this->resetPosition();
    }

    /**
     * Resets the internal counters to zero.
     *
     * This method is used by the `reset` method to reset the internal counters to zero.
     */
    private function resetPosition(): void
    {
        $this->count = 0;
        $this->position = 0;
    }

    /**
     * Character iterator.
     *
     * Iterates over the file, yielding one character at a time.
     *
     * @return Generator<int, string> A generator yielding individual characters from the file.
     */
    private function characterIterator(): Generator
    {
        while (! $this->file->eof()) {
            yield $this->file->fgetc();
            $this->position++;
            $this->count++;
        }
    }

    /**
     * Line iterator.
     *
     * Iterates over the file line by line, yielding each line.
     *
     * @return Generator<int, string> A generator yielding lines from the file.
     */
    private function lineIterator(): Generator
    {
        while (! $this->file->eof()) {
            yield $this->file->fgets();
            $this->position++;
            $this->count++;
        }
    }

    /**
     * CSV iterator.
     *
     * Iterates over the file, parsing each line as CSV and yielding an array of fields.
     *
     * @param  string  $separator  The field delimiter (one character only). Default is ','.
     * @param  string  $enclosure  The field enclosure character (one character only). Default is '"'.
     * @param  string  $escape  The escape character (one character only). Default is '\\'.
     * @return Generator<int, array<string>> A generator yielding arrays of CSV fields.
     */
    private function csvIterator(string $separator = ',', string $enclosure = '"', string $escape = '\\'): Generator
    {
        while (! $this->file->eof()) {
            $csvLine = $this->file->fgetcsv($separator, $enclosure, $escape);
            if ($csvLine !== false) {
                yield $csvLine;
                $this->position++;
                $this->count++;
            }
        }
    }

    /**
     * Binary data iterator.
     *
     * Iterates over the file, reading and yielding binary data in specified byte chunks.
     *
     * @param  int  $bytes  The number of bytes to read in each iteration. Default is 1024.
     * @return Generator<int, string> A generator yielding binary strings of the specified size.
     */
    private function binaryIterator(int $bytes = 1024): Generator
    {
        while (! $this->file->eof()) {
            yield $this->file->fread($bytes);
            $this->position++;
            $this->count++;
        }
    }

    /**
     * JSON line-by-line iterator.
     *
     * Iterates over each line in the file, decoding it as JSON and yielding the resulting object.
     *
     * @return Generator<int, array<string, mixed>, mixed, void> JSON objects from each line.
     */
    private function jsonIterator(): Generator
    {
        while (! $this->file->eof()) {
            $line = trim($this->file->fgets());
            if ($line) {
                yield json_decode($line, true);
                $this->position++;
                $this->count++;
            }
        }
    }

    /**
     * Regex iterator for pattern matching.
     *
     * Iterates over each line in the file, matching it against the provided regex pattern.
     * Yields matches found in each line.
     *
     * @param  string  $pattern  The regex pattern to match against each line.
     * @return Generator<int, array<int, string>> A generator yielding arrays of matches per line.
     */
    private function regexIterator(string $pattern): Generator
    {
        while (! $this->file->eof()) {
            $line = $this->file->fgets();
            if (preg_match($pattern, $line, $matches)) {
                yield $matches;
                $this->position++;
                $this->count++;
            }
        }
    }

    /**
     * Fixed-width field iterator.
     *
     * Iterates over each line in the file, splitting it into fields based on the provided widths.
     *
     * @param  array<int>  $widths  An array of widths for each field.
     * @return Generator<int, array<string>, mixed, void> Fields from each line.
     */
    private function fixedWidthIterator(array $widths): Generator
    {
        while (! $this->file->eof()) {
            $line = $this->file->fgets();
            $fields = [];
            $offset = 0;
            foreach ($widths as $width) {
                $fields[] = substr($line, $offset, $width);
                $offset += $width;
            }
            yield $fields;
            $this->position++;
            $this->count++;
        }
    }

    /**
     * XML iterator for element-by-element parsing.
     *
     * @param  string  $element  The XML element to iterate over.
     * @return Generator<SimpleXMLElement> A generator of SimpleXMLElement objects.
     *
     * @throws Exception
     */
    private function xmlIterator(string $element): Generator
    {
        $currentElement = '';
        while (! $this->file->eof()) {
            $line = $this->file->fgets();
            $currentElement .= $line;
            if (stripos($line, "</$element>") !== false) {
                yield new SimpleXMLElement($currentElement);
                $currentElement = '';
                $this->position++;
                $this->count++;
            }
        }
    }

    /**
     * Serialized object iterator.
     *
     * Iterates over each serialized line in the file, unserializing and yielding the object.
     *
     * @return Generator<int, mixed> Unserialized objects from each line.
     */
    private function serializedIterator(): Generator
    {
        while (! $this->file->eof()) {
            $serializedLine = $this->file->fgets();
            if ($serializedLine) {
                yield unserialize($serializedLine);
                $this->position++;
                $this->count++;
            }
        }
    }

    /**
     * JSON array iterator, yielding each element of the array.
     *
     * @return Generator<int, mixed>
     */
    private function jsonArrayIterator(): Generator
    {
        $jsonArray = json_decode($this->file->fread($this->file->getSize()), true);
        foreach ($jsonArray as $element) {
            yield $element;
            $this->position++;
            $this->count++;
        }
    }
}
