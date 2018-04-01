<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\{UnsupportedVariableTypeException, InvalidArrayFormatException,
	CircularReferencesException, InvalidDataException};

class Validator
{
	protected $recursionCheckObject;

	public function ensureInteger($value)
	{
		if (!is_int($value))
			throw new UnsupportedVariableTypeException;
	}

	public function ensureString($value)
	{
		if (!is_string($value))
			throw new UnsupportedVariableTypeException;
	}

	public function ensureStringOrNull($value)
	{
		if (!is_string($value) && $value !== null)
			throw new UnsupportedVariableTypeException;
	}

	public function ensureArrayOrNull($value)
	{
		if (!is_array($value) && $value !== null)
			throw new UnsupportedVariableTypeException;
	}

	public function ensureArrayOrTrueOrNull($value)
	{
		if (!is_array($value) && $value !== null && $value !== true)
			throw new UnsupportedVariableTypeException;
	}

	public function ensureFlatArray(array $array)
	{
		if (count($array) !== count($array, COUNT_RECURSIVE))
			throw new InvalidArrayFormatException;

		foreach ($array as $element)
			if (is_array($element))
				throw new InvalidArrayFormatException;
	}

	public function ensureHeadersArray(array $headers)
	{
		$this->ensureNoCircularReferences($headers);
		$this->ensureSupportedVariableTypes($headers);

		foreach ($headers as $header => $values) {
			if (!is_array($values)) {
				throw new InvalidArrayFormatException;
			}

			if (count($values) !== count($values, COUNT_RECURSIVE)) {
				throw new InvalidArrayFormatException;
			}

			if (array_keys($values) !== range(0, count($values) - 1)) {
				throw new InvalidArrayFormatException;
			}

			foreach ($values as $value) {
				if (is_array($value)) {
					throw new InvalidArrayFormatException;
				}
			}
		}
	}

	public function ensureUploadsArray(array $uploads)
	{
		$this->ensureNoCircularReferences($uploads);
		$this->ensureSupportedVariableTypes($uploads);

		foreach ($uploads as $upload) {
			$keys = array_keys($upload);
			sort($keys);
			$keys = array_values($keys);
			if ($keys !== ['filename', 'name', 'signature'])
				throw new InvalidArrayFormatException;
		}
	}

	public function ensureNoCircularReferences(array &$array, array &$alreadySeen = [])
	{
		if (!$this->recursionCheckObject)
			$this->recursionCheckObject = new \stdClass();

		$alreadySeen[] = &$array;

		foreach ($array as &$item) {
			if (!is_array($item))
				continue;

			$item[] = $this->recursionCheckObject;
			$recursionDetected = false;

			foreach ($alreadySeen as $candidate) {
				if (end($candidate) === $this->recursionCheckObject) {
					$recursionDetected = true;
					break;
				}
			}

			array_pop($item);

			if ($recursionDetected || $this->ensureNoCircularReferences($item, $alreadySeen))
				throw new CircularReferencesException;
		}
	}

	public function ensureSupportedVariableTypes($array)
	{
		$array = (array) $array;

		foreach ($array as $item) {
			if (is_array($item)) {
				$this->ensureSupportedVariableTypes($item);
				continue;
			}

			if (!in_array(gettype($item), ['boolean', 'integer', 'double', 'string', 'NULL']))
				throw new UnsupportedVariableTypeException;
		}
	}

	public function ensureValidUtf8($value)
	{
		if (!mb_check_encoding($value, 'UTF-8'))
			throw new UnsupportedVariableTypeException;
	}

	public function checkBinHexFormat($value, $length = null)
	{
		if ($length !== null && $length % 2 !== 0)
			throw new InvalidDataException;

		$result = preg_match('/^[\da-f]' . ($length ? '{' . $length . '}' : '+') . '$/siu', $value);

		if (!$result)
			throw new InvalidDataException;

		if ($length === null && strlen($value) % 2 !== 0)
			throw new InvalidDataException;

		return $result;
	}

	public function checkArrayBinHexFormat(array $array, $length_in_bytes = null)
	{
		foreach ($array as $value) {
			if (is_array($value))
				$this->checkArrayBinHexFormat($value, $length_in_bytes);
			else
				$this->checkBinHexFormat($value, $length_in_bytes);
		}
	}
}
