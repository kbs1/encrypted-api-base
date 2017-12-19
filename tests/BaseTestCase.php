<?php

use PHPUnit\Framework\TestCase;

use Kbs1\EncryptedApiBase\Exceptions\Cryptography\InvalidSharedSecretException;

abstract class BaseTestCase extends TestCase
{
	abstract protected function getClass();
	abstract protected function defaultConstructorArguments();
	abstract protected function mockMethods();

	/*
	 * Base test methods
	 */

	protected function expectsInstance(array $arguments_merge = [])
	{
		$class = $this->getClass();
		$this->assertInstanceOf($class, $instance = new $class(...$this->constructorArguments($arguments_merge)));
		return $instance;
	}

	protected function expectsMockInstance(array $arguments_merge = [])
	{
		$mock_methods = $this->mockMethods();
		$instance = $this->getMockBuilder($this->getClass())->setMethods(array_keys($mock_methods))->setConstructorArgs($this->constructorArguments($arguments_merge))->getMock();

		foreach ($mock_methods as $method => $closure)
			$instance->method($method)->will($this->returnCallback($closure));

		$this->assertInstanceOf($this->getClass(), $instance);
		return $instance;
	}

	protected function expectsException($exception_class, array $arguments_merge = [])
	{
		$class = $this->getClass();
		$this->expectException($exception_class);
		return $this->expectsInstance($arguments_merge);
	}

	protected function expectsMockException($exception_class, array $arguments_merge = [])
	{
		$class = $this->getClass();
		$this->expectException($exception_class);
		return $this->expectsMockInstance($arguments_merge);
	}

	protected function constructorArguments(array $merge = [])
	{
		$default_args = $this->defaultConstructorArguments();
		$merged = $merge + $default_args;
		$args = [];

		foreach ($default_args as $key => $arg)
			$args[] = $merged[$key];

		return $args;
	}

	protected function callableMethod($method_name)
	{
		$method = new ReflectionMethod($this->getClass(), $method_name);
        $method->setAccessible(true);

        return $method;
	}

	protected function circularReferencedArray()
	{
		$a = ['foo' => 'bar'];
		$a[4] = &$a;

		return $a;
	}

	protected function invalidUtf8String()
	{
		return "abc\x00\xffcde";
	}

	protected function deepArray($levels)
	{
		$a = ['el' => rand()];
		$cur = &$a;

		for ($level = 0; $level < $levels - 1; $level++) {
			$cur['el2'] = ['el' => rand()];
			$cur = &$cur['el2'];
		}

		unset($cur);

		return $a;
	}

	protected function arrayDepth(array $array)
	{
		$max_depth = 1;

		foreach ($array as $value) {
			if (is_array($value)) {
				$depth = $this->arrayDepth($value) + 1;

				if ($depth > $max_depth) {
					$max_depth = $depth;
				}
			}
		}

		return $max_depth;
	}

	/*
	 * Shared secrets tests
	 */

	public function testInvalidSharedSecrets1()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => null]);
	}

	public function testInvalidSharedSecrets2()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => null]);
	}

	public function testInvalidSharedSecrets3()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => M_PI]);
	}

	public function testInvalidSharedSecrets4()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => M_PI]);
	}

	public function testInvalidSharedSecrets5()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => 'foo']);
	}

	public function testInvalidSharedSecrets6()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => 'foo']);
	}

	public function testInvalidSharedSecrets7()
	{
		$secret = range(0, 31);
		$secret[31] = 'foo';
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets8()
	{
		$secret = range(0, 31);
		$secret[31] = 'foo';
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets9()
	{
		$secret = range(0, 31);
		$secret[16] = -1;
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets10()
	{
		$secret = range(0, 31);
		$secret[16] = -1;
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets11()
	{
		$secret = range(0, 31);
		$secret[16] = 256;
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets12()
	{
		$secret = range(0, 31);
		$secret[16] = 256;
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets13()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => fopen('php://temp', 'r+')]);
	}

	public function testInvalidSharedSecrets14()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => fopen('php://temp', 'r+')]);
	}

	public function testInvalidSharedSecrets15()
	{
		$secret = range(0, 31);
		$secret[13] = fopen('php://temp', 'r+');
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => $secret]);
	}

	public function testInvalidSharedSecrets16()
	{
		$secret = range(0, 31);
		$secret[13] = fopen('php://temp', 'r+');
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => $secret]);
	}

	public function testInvalidSharedSecrets17()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => range(0, 90), 'secret2' => range(0, 90)]);
	}

	public function testInvalidSharedSecrets18()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets19()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912x', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets20()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912x']);
	}

	public function testInvalidSharedSecrets21()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '0123456789012345678901234567891']);
	}

	public function testInvalidSharedSecrets22()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => '0123456789012345678901234567891']);
	}

	public function testInvalidSharedSecrets23()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => range(0, 30)]);
	}

	public function testInvalidSharedSecrets24()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret2' => range(0, 30)]);
	}

	public function testInvalidSharedSecrets25()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => 'x01234567890123456789012345678912', 'secret2' => '01234567890123456789012345678912']);
	}

	public function testInvalidSharedSecrets26()
	{
		$this->expectsException(InvalidSharedSecretException::class, ['secret1' => '01234567890123456789012345678912', 'secret2' => 'x01234567890123456789012345678912']);
	}

	public function testValidSharedSecrets1()
	{
		$this->expectsInstance(['secret1' => str_repeat($this->invalidUtf8String(), 4)]);
	}

	public function testValidSharedSecrets2()
	{
		$this->expectsInstance(['secret2' => str_repeat($this->invalidUtf8String(), 4)]);
	}
}
