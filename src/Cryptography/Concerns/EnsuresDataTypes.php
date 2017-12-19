<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\UnsupportedVariableTypeException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidArrayFormatException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\CircularReferencesException;

trait EnsuresDataTypes
{
	protected $recursionCheckObject;

	protected function ensureString($value)
	{
		if (!is_string($value))
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureStringOrNull($value)
	{
		if (!is_string($value) && $value !== null)
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureStringOrArray($value)
	{
		if (!is_string($value) && !is_array($value))
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureStringOrArrayOrNull($value)
	{
		if (!is_string($value) && !is_array($value) && $value !== null)
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureHeadersArray(array $headers)
	{
		$this->ensureNoCircularReferences($headers);
		$this->ensureSupportedVariableTypes($headers);

		foreach ($headers as $header => $values) {
			if (!is_array($values)) {
				throw new InvalidArrayFormatException();
			}

			if (count($values) !== count($values, COUNT_RECURSIVE)) {
				throw new InvalidArrayFormatException();
			}

			if (array_keys($values) !== range(0, count($values) - 1)) {
				throw new InvalidArrayFormatException();
			}

			foreach ($values as $value) {
				if (is_array($value)) {
					throw new InvalidArrayFormatException();
				}
			}
		}
	}

	protected function ensureNoCircularReferences(array &$array, array &$alreadySeen = [])
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
				throw new CircularReferencesException();
		}
	}

	protected function ensureSupportedVariableTypes(array $array)
	{
		foreach ($array as $item) {
			if (is_array($item)) {
				$this->ensureSupportedVariableTypes($item);
				continue;
			}

			if (!in_array(gettype($item), ['boolean', 'integer', 'double', 'string', 'NULL']))
				throw new UnsupportedVariableTypeException();
		}
	}

	protected function ensureValidUtf8($value)
	{
		if (!mb_check_encoding($value, 'UTF-8'))
			throw new UnsupportedVariableTypeException();
	}
}
