<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

class Payload
{
	protected $validator, $cipher, $json, $timestampGenerator;
	protected $headers, $data, $provided_id, $id, $provided_timestamp, $timestamp, $url, $method, $uploads;

	protected $id_length = 32;

	public function __construct()
	{
		$this->validator = new Validator;
		$this->cipher = new Cipher;
		$this->json = new Json;
		$this->timestampGenerator = new Timestamp;
	}

	public function getTransmit()
	{
		return $this->json->encode($this->getOriginal());
	}

	public function getOriginal()
	{
		return [
			'id' => $this->getId(),
			'timestamp' => $this->getTimestamp(),
			'headers' => $this->getHeaders(),
			'data' => $this->getData(),
			'uploads' => $this->getUploads(),
			'url' => $this->getUrl(),
			'method' => $this->getMethod(),
		];
	}

	public function fromTransmit($transmit)
	{
		$json = $this->json->decodeAndEnsureKeys($transmit, ['id', 'timestamp', 'headers', 'data', 'uploads', 'url', 'method']);

		$this->setId($json['id']);
		$this->setTimestamp($json['timestamp']);
		$this->setHeaders($json['headers']);
		$this->setData($json['data']);
		$this->setUploads($json['uploads']);
		$this->setUrl($json['url']);
		$this->setMethod($json['method']);
	}

	public function setHeaders(array $headers)
	{
		$this->validator->ensureHeadersArray($headers);
		$this->headers = $headers;
		return $this;
	}

	public function getHeaders()
	{
		return $this->headers;
	}

	public function setData($data)
	{
		$this->validator->ensureStringOrNull($data);
		$this->data = $data;

		return $this;
	}

	public function getData()
	{
		return $this->data;
	}

	public function setId($id)
	{
		$this->validator->ensureStringOrNull($id);

		if ($id !== null)
			$this->validator->checkBinHexFormat($id, $this->getIdLength() * 2);

		$this->provided_id = $id;
		return $this;
	}

	public function getId()
	{
		return $this->id ?? ($this->provided_id ?? $this->id = bin2hex($this->cipher->generateRandomBytes($this->getIdLength())));
	}

	public function getIdLength()
	{
		return $this->id_length;
	}

	public function setTimestamp($timestamp)
	{
		$this->validator->ensureInteger($timestamp);
		$this->provided_timestamp = $timestamp;
		return $this;
	}

	public function getTimestamp()
	{
		return $this->timestamp ?? ($this->provided_timestamp ?? $this->timestamp = $this->timestampGenerator->getCurrentTimestamp());
	}

	public function setUrl($url)
	{
		$this->validator->ensureStringOrNull($url);
		$this->url = $url;
		return $this;
	}

	public function getUrl()
	{
		return $this->url;
	}

	public function setMethod($method)
	{
		$this->validator->ensureStringOrNull($method);
		$this->method = $method;
		return $this;
	}

	public function getMethod()
	{
		return $this->method === null ? null : strtolower($this->method);
	}

	public function setUploads($uploads)
	{
		$this->validator->ensureArrayOrTrueOrNull($uploads);

		if (is_array($uploads))
			$this->validator->ensureUploadsArray($uploads);

		$this->uploads = $uploads;
		return $this;
	}

	public function getUploads()
	{
		return $this->uploads;
	}
}
