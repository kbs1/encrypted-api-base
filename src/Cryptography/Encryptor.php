<?php

namespace Kbs1\EncryptedApi\Cryptography;

use Kbs1\EncryptedApi\Exceptions\Decryption\WeakRandomBytesException;
use Kbs1\EncryptedApi\Exceptions\Decryption\CircularReferencesException;
use Kbs1\EncryptedApi\Exceptions\Decryption\InvalidArrayFormatException;
use Kbs1\EncryptedApi\Exceptions\Decryption\UnableToEncodeAsBase64Exception;
use Kbs1\EncryptedApi\Exceptions\Decryption\UnableToEncodeAsJsonException;
use Kbs1\EncryptedApi\Exceptions\Decryption\UnsupportedVariableTypeException;

class Encryptor extends Base
{
	protected $headers, $data, $force_id, $used_id, $url, $method;
	protected $recursionCheckObject;

	public function __construct(array $headers, $data, $secret1, $secret2, $force_id = null, $url = null, $method = null)
	{
		$this->ensureNoCircularReferences($headers);
		$this->ensureSupportedVariableTypes($headers);
		$this->ensureFlatArray($headers);

		$this->ensureStringOrArrayOrNull($data);

		if (is_array($data)) {
			$this->ensureNoCircularReferences($data);
			$this->ensureSupportedVariableTypes($data);
		}

		$this->ensureStringOrNull($force_id);
		$this->ensureStringOrNull($url);
		$this->ensureStringOrNull($method);

		$this->headers = $headers;
		$this->data = $data;

		$this->force_id = $force_id;

		$this->url = $url;
		$this->method = $method;

		$this->recursionCheckObject = new \stdClass();

		parent::__construct($secret1, $secret2);
	}

	public function encrypt()
	{
		$iv = $this->getRandomBytes($this->iv_length);

		$data = [
			'id' => $this->used_id = $this->force_id ?? $this->getRandomBytes($this->id_length),
			'timestamp' => time(),
			'headers' => $this->encodeBase64Array($this->headers),
			'data' => $this->data === null ? null : (is_string($this->data) ? $this->encodeBase64($this->data) : $this->encodeBase64Array($this->data)),
			'url' => $this->encodeBase64($this->url),
			'method' => $this->encodeBase64(strtolower($this->method)),
		];

		$encrypted = bin2hex(openssl_encrypt($this->encodeJson($data), $this->data_algorithm, $this->getSecret1(), OPENSSL_RAW_DATA, hex2bin($iv)));
		$signature = hash_hmac($this->signature_algorithm, $encrypted . $iv, $this->getSecret2());

		$this->checkDataFormat($encrypted);
		$this->checkIvFormat($iv);
		$this->checkSignatureFormat($signature);
		$this->checkIdFormat($this->getId());

		return $this->encodeJson(['data' => $encrypted, 'iv' => $iv, 'signature' => $signature]);
	}

	public function getId()
	{
		return $this->used_id;
	}

	protected function getRandomBytes($length)
	{
		$bytes = openssl_random_pseudo_bytes($length, $is_strong);
		if (!$is_strong)
			throw new WeakRandomBytesException();

		return bin2hex($bytes);
	}

	protected function encodeBase64($value)
	{
		$result = base64_encode($value);
		if ($value === false)
			throw new UnableToEncodeAsBase64Exception();

		return $value;
	}

	protected function encodeBase64Array(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->encodeBase64($key)] = $this->encodeBase64Array($value);
			else
				$result[$this->encodeBase64($key)] = $this->encodeBase64($value);

		return $result;
	}

	protected function encodeJson($value)
	{
		$result = @json_encode($value);
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new UnableToEncodeAsJsonException(json_last_error_msg());

		return $result;
	}

	protected function ensureStringOrNull($value)
	{
		if (!is_string($value) && $value !== null)
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureStringOrArrayOrNull($value)
	{
		if (!is_string($value) && !is_array($value) && $value !== null)
			throw new UnsupportedVariableTypeException();
	}

	protected function ensureFlatArray(array &$array)
	{
		if (count($array) !== count($array, COUNT_RECURSIVE))
			throw new InvalidArrayFormatException();
	}

	protected function ensureNoCircularReferences(array &$array, array &$alreadySeen = [])
	{
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
}
