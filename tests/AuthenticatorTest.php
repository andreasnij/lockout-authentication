<?php

use LockoutAuthentication\Authenticator;

class AuthenticatorTest extends PHPUnit_Framework_TestCase
{
    private $authenticator;
    private $mockAuthenticatableUser;
    private $password;
    private $passwordHash;

    public function setUp()
    {
        $this->authenticator = new Authenticator([
            'hashAlgorithm' => PASSWORD_DEFAULT,
            'hashOptions' => ['cost' => 9],
            'attemptsBeforeLockout' => 2,
            'lockoutClearTime' => 600,
        ]);

        $this->password = '123';
        $this->passwordHash = $this->authenticator->createPasswordHash($this->password);

        $this->mockAuthenticatableUser = $this->getMock('\SimpleAuthentication\AuthenticatableUserInterface');
        $this->mockAuthenticatableUser->expects($this->any())
            ->method('getPasswordHash')
            ->will($this->returnValue($this->passwordHash));
    }

    /**
     * @covers SimpleAuthentication\Authenticator::__construct
     * @covers SimpleAuthentication\Authenticator::authenticate
     * @covers SimpleAuthentication\Authenticator::isLoginBlocked
     * @covers SimpleAuthentication\Authenticator::shouldLockoutBeCleared
     */
    public function testAuthenticateBlocked()
    {
        $this->mockAuthenticatableUser->expects($this->any())
            ->method('getLoginBlockedUntilTime')
            ->will($this->returnValue(time() + 10));

        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertFalse($result);
        $this->assertTrue($this->authenticator->isLoginBlocked($this->mockAuthenticatableUser));
    }

    /**
     * @covers SimpleAuthentication\Authenticator::authenticate
     * @covers SimpleAuthentication\Authenticator::clearLockout
     */
    public function testAuthenticateSuccess()
    {
        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertTrue($result);
    }

    /**
     * @covers SimpleAuthentication\Authenticator::authenticate
     * @covers SimpleAuthentication\Authenticator::createPasswordHash
     */
    public function testAuthenticateSuccessWithRehash()
    {
        $newAuthenticator = new Authenticator(['hashOptions' => ['cost' => 5]]); // Create new authenticator with options so that rehash code will be run
        $result = $newAuthenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertTrue($result);
    }

    /**
     * @covers SimpleAuthentication\Authenticator::authenticate
     * @covers SimpleAuthentication\Authenticator::shouldLockoutBeCleared
     * @covers SimpleAuthentication\Authenticator::addFailedLoginAttempt
     */
    public function testAuthenticateFail()
    {
        $this->mockAuthenticatableUser->expects($this->any())
            ->method('getFailedLoginAttempts')
            ->will($this->returnValue(5));

        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, 'invalid-password');
        $this->assertFalse($result);
    }

    /**
     * @covers SimpleAuthentication\Authenticator::createPasswordHash
     */
    public function testCreatePasswordHashFail()
    {
        // Try to authenticate with non existent algorithm
        $authenticatior = new Authenticator(['hashAlgorithm' => 123]);
        $this->setExpectedException('\RuntimeException');
        $authenticatior->createPasswordHash($this->password);
    }


}
