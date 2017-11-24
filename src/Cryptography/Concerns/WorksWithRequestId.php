<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

trait WorksWithRequestId
{
	protected $id_length = 32;

	public function getIdLength()
	{
		return $this->id_length;
	}
}
