<?php

namespace Kbs1\EncryptedApiBase\Cryptography;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsBase64Exception;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\Encryption\UnableToEncodeAsJsonException;
use Kbs1\EncryptedApiBase\Exceptions\Cryptography\UnsupportedVariableTypeException;

use Kbs1\EncryptedApiBase\Cryptography\Concerns\EnsuresDataTypes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\HandlesSharedSecrets;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithCipher;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\GeneratesRandomBytes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithRequestId;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithTimestamp;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\WorksWithUploadHashes;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ComputesSignature;
use Kbs1\EncryptedApiBase\Cryptography\Concerns\ChecksBinHexFormat;

class Encryptor
{
	use EnsuresDataTypes, HandlesSharedSecrets, WorksWithCipher, GeneratesRandomBytes, WorksWithRequestId, WorksWithTimestamp, WorksWithUploadHashes, ComputesSignature, ChecksBinHexFormat;

	protected $headers, $data, $force_id, $used_id, $url, $method, $uploads;

	public function __construct(array $headers, $data, $secret1, $secret2, $force_id = null, $url = null, $method = null, $uploads = null)
	{
		$this->ensureHeadersArray($headers);

		$this->ensureStringOrArrayOrNull($data);

		if (is_array($data)) {
			$this->ensureNoCircularReferences($data);
			$this->ensureSupportedVariableTypes($data);
		}

		$this->ensureStringOrNull($force_id);
		$this->ensureStringOrNull($url);
		$this->ensureStringOrNull($method);
		$this->ensureArrayOrNull($uploads);

		if ($uploads) {
			$this->ensureUploadsArray($uploads);
			$this->checkArrayBinHexFormat($uploads, $this->getUploadHashLength());
		}

		$this->headers = $headers;
		$this->data = $data;

		if ($force_id)
			$this->checkBinHexFormat($force_id, $this->getIdLength());

		$this->force_id = $force_id;

		$this->url = $url;
		$this->method = $method;
		$this->uploads = $uploads;

		$this->setSharedSecrets($secret1, $secret2);
	}

	public function encrypt()
	{
		$data = $this->getRequestData();

		$iv = $this->generateRandomBytes($this->getIvLength());
		$encrypted = $this->encryptString($this->encodeJson($data), $iv, $this->secret1);
		$signature = $this->computeSignature(bin2hex($encrypted) . bin2hex($iv), $this->secret2);

		return $this->encodeJson(['data' => bin2hex($encrypted), 'iv' => bin2hex($iv), 'signature' => bin2hex($signature)]);
	}

	public function getId()
	{
		return $this->used_id;
	}

	protected function getRequestData()
	{
		return [
			'id' => $this->used_id = $this->force_id ?? bin2hex($this->generateRandomBytes($this->getIdLength())),
			'timestamp' => $this->getCurrentTimestamp(),
			'headers' => $this->jsonTransmittableArray($this->headers),
			'data' => $this->data === null ? null : (is_string($this->data) ? $this->jsonTransmittableValue($this->data) : $this->jsonTransmittableArray($this->data)),
			'uploads' => $this->uploads,
			'url' => $this->jsonTransmittableValue($this->url),
			'method' => $this->jsonTransmittableValue($this->method === null ? null : strtolower($this->method)),
		];
	}

	protected function encodeBase64($value)
	{
		$result = base64_encode($value);
		if ($result === false)
			throw new UnableToEncodeAsBase64Exception();

		return $result;
	}

	protected function jsonTransmittableValue($value)
	{
		if (!is_string($value))
			return $value;

		try {
			$this->ensureValidUtf8($value);
		} catch (UnsupportedVariableTypeException $ex) {
			return 'b' . $this->encodeBase64($value);
		}

		return 'u' . $value;
	}

	protected function jsonTransmittableArray(array $array)
	{
		$result = [];

		foreach ($array as $key => $value)
			if (is_array($value))
				$result[$this->jsonTransmittableValue($key)] = $this->jsonTransmittableArray($value);
			else
				$result[$this->jsonTransmittableValue($key)] = $this->jsonTransmittableValue($value);

		return $result;
	}

	protected function encodeJson($value)
	{
		$result = @json_encode($value, 0, 513);
		if (json_last_error() !== JSON_ERROR_NONE)
			throw new UnableToEncodeAsJsonException(json_last_error_msg());

		return $result;
	}
}
