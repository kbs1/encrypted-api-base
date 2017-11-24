<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidDataException;

trait ChecksBinHexFormat
{
	protected function checkBinHexFormat($value, $length_in_bytes = null)
	{
		$result = preg_match('/^[\da-f]' . ($length_in_bytes ? '{' . ($length_in_bytes * 2) . '}' : '+') . '$/siu', $value);

		if (!$result)
			throw new InvalidDataException();

		if ($length_in_bytes === null && strlen($value) % 2 !== 0)
			throw new InvalidDataException();

		return $result;
	}
}
