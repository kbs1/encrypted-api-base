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

	protected function ensureArray(array $array)
	{
		if (!is_array($array))
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureFlatArray(array $array)
	{
		$this->ensureArray($array);

		if (count($array) !== count($array, COUNT_RECURSIVE))
			throw new InvalidArrayFormatException();
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
			if (is_array($item))
				$this->ensureSupportedVariableTypes($item);

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
