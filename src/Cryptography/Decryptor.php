<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\Decryption\InvalidDataException;
use Kbs1\EncryptedApi\Exceptions\Decryption\InvalidSignatureException;
use Kbs1\EncryptedApi\Exceptions\Decryption\InvalidTimestampException;
use Kbs1\EncryptedApi\Exceptions\Decryption\UnableToDecodeBase64Exception;

class Decryptor extends Base
{
	protected $data;

	public function __construct($data, $secret1, $secret2)
	{
		$this->ensureString($data);
		$this->data = $data;

		parent::__construct($secret1, $secret2);
	}

	public function decrypt()
	{
		$input = $this->parse();
		$this->verifySignature($input);
		$decrypted = $this->decryptData($input);
		$this->checkIdFormat($decrypted['id']);
		$this->verifyTimestamp($decrypted);
		$original = $this->decode($decrypted);

		return $original;
	}

	protected function parse()
	{
		$input = $this->decodeAndCheckJson($this->data, ['signature', 'iv', 'data']);

		$this->checkSignatureFormat($input['signature']);
		$this->checkIvFormat($input['iv']);
		$this->checkDataFormat($input['data']);

		return $input;
	}

	protected function verifySignature($input)
	{
		$expected = hash_hmac($this->signature_algorithm, $input['data'] . $input['iv'], $this->getSecret2());

		if (!hash_equals($expected, $input->signature))
			throw new InvalidSignatureException();
	}

	protected function decryptData($input)
	{
		$decrypted = @openssl_decrypt(hex2bin($input['data']), $this->data_algorithm, $this->getSecret1(), OPENSSL_RAW_DATA, hex2bin($input['iv']));

		if ($decrypted === false)
			throw new InvalidDataException();

		return $this->decodeAndCheckJson($decrypted, ['id', 'timestamp', 'headers', 'data', 'url', 'method']);
	}

	protected function verifyTimestamp($data)
	{
		if (!is_numeric($data['timestamp']) || $data['timestamp'] < time() - 10)
			throw new InvalidTimestampException();
	}

	protected function decode(array $input)
	{
		$input['headers'] = $this->decodeBase64Array($input['headers']);

		if (is_array($input['data']))
			$input['data'] = $this->decodeBase64Array($input['data']);
		if (is_string($input['data']))
			$input['data'] = $this->decodeBase64($input['data']);

		$input['url'] = $this->decodeBase64($input['url']);
		$input['method'] = $this->decodeBase64($input['method']);

		return $input;
	}

	protected function decodeBase64($value)
	{
		$result = @base64_decode($value);
		if ($value === false)
			throw new UnableToDecodeBase64Exception();

		return $value;
	}

	protected function decodeBase64Array(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->decodeBase64($key)] = $this->decodeBase64Array($value);
			else
				$result[$this->decodeBase64($key)] = $this->decodeBase64($value);

		return $result;
	}

	protected function decodeAndCheckJson($input, array $expected_keys)
	{
		$result = @json_decode($input, true);

		if (json_last_error() !== JSON_ERROR_NONE)
			throw new InvalidDataException();

		$keys = array_keys($result);
		sort($keys);
		sort($expected_keys);

		if ($keys !== $expected_keys)
			throw new InvalidDataException();

		return $result;
	}
}
