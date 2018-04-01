<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Support;

class Envelope
{
	protected $data, $iv, $sign;
	protected $validator, $secrets, $cipher, $json, $signature;

	public function __construct(SharedSecrets $secrets)
	{
		$this->validator = new Validator;
		$this->secrets = $secrets;
		$this->cipher = new Cipher;
		$this->json = new Json;
		$this->signature = new Signature;
	}

	public function getTransmit()
	{
		return $this->json->encode([
			'data' => $this->getData(),
			'iv' => $this->getIv(),
			'signature' => $this->getSignature(),
		]);
	}

	public function fromTransmit($transmit)
	{
		$this->validator->ensureString($transmit);
		$json = $this->json->decodeAndEnsureKeys($transmit, ['data', 'iv', 'signature']);

		$this->setData($json['data']);
		$this->setIv($json['iv']);
		$this->setSignature($json['signature']);
	}

	public function carryPayload(Payload $payload)
	{
		$this->setIv(bin2hex($this->cipher->generateRandomBytes($this->cipher->getIvLength())));
		$this->setData(bin2hex($this->cipher->encryptString($payload->getTransmit(), hex2bin($this->getIv()), $this->secrets->getSecret1())));
		$this->setSignature(bin2hex($this->signature->compute($this->getData() . $this->getIv(), $this->secrets->getSecret2())));
	}

	public function extractPayload()
	{
		$this->signature->verify($this->getData() . $this->getIv(), hex2bin($this->getSignature()), $this->secrets->getSecret2());
		$transmit = $this->cipher->decryptString(hex2bin($this->getData()), hex2bin($this->getIv()), $this->secrets->getSecret1());

		$payload = new Payload;
		$payload->fromTransmit($transmit);

		return $payload;
	}

	public function setData($data)
	{
		$this->validator->checkBinHexFormat($data);
		$this->data = $data;
		return $this;
	}

	public function getData()
	{
		return $this->data;
	}

	public function setIv($iv)
	{
		$this->validator->checkBinHexFormat($iv, $this->cipher->getIvLength() * 2);
		$this->iv = $iv;
		return $this;
	}

	public function getIv()
	{
		return $this->iv;
	}

	public function setSignature($signature)
	{
		$this->validator->checkBinHexFormat($signature, $this->signature->getLength() * 2);
		$this->sign = $signature;
		return $this;
	}

	public function getSignature()
	{
		return $this->sign;
	}
}
