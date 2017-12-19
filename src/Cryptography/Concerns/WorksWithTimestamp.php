<?php

namespace Kbs1\EncryptedApiBase\Cryptography\Concerns;

trait WorksWithTimestamp
{
	protected function getCurrentTimestamp()
	{
		return time();
	}
}
