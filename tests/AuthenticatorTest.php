<?php

namespace LockoutAuthentication\Tests;

use LockoutAuthentication\Authenticator;
use LockoutAuthentication\AuthenticatableUserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class AuthenticatorTest extends TestCase
{
    private Authenticator $authenticator;
    private string $password;

    /** @var MockObject&AuthenticatableUserInterface  */
    private MockObject $mockAuthenticatableUser;

    protected function setUp(): void
    {
        $this->authenticator = new Authenticator([
            'hashAlgorithm' => PASSWORD_DEFAULT,
            'hashOptions' => ['cost' => 9],
            'attemptsBeforeLockout' => 2,
            'lockoutClearTime' => 600,
        ]);

        $this->password = '123';
        $passwordHash = $this->authenticator->createPasswordHash($this->password);

        $this->mockAuthenticatableUser = $this->createMock(AuthenticatableUserInterface::class);
        $this->mockAuthenticatableUser->method('getPasswordHash')
            ->willReturn($passwordHash);
    }

    public function testAuthenticateBlocked()
    {
        $this->mockAuthenticatableUser->expects($this->any())
            ->method('getLoginBlockedUntilTime')
            ->willReturn(time() + 10);

        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertFalse($result);
        $this->assertTrue($this->authenticator->isLoginBlocked($this->mockAuthenticatableUser));
    }

    public function testAuthenticateSuccess()
    {
        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertTrue($result);
    }

    public function testAuthenticateSuccessWithRehash(): void
    {
        // Create new authenticator with options so that rehash code will be run
        $newAuthenticator = new Authenticator(['hashOptions' => ['cost' => 5]]);
        $result = $newAuthenticator->authenticate($this->mockAuthenticatableUser, $this->password);
        $this->assertTrue($result);
    }

    public function testAuthenticateFail()
    {
        $this->mockAuthenticatableUser->expects($this->any())
            ->method('getFailedLoginAttempts')
            ->willReturn(5);

        $result = $this->authenticator->authenticate($this->mockAuthenticatableUser, 'invalid-password');
        $this->assertFalse($result);
    }

    public function testCreatePasswordHashFail()
    {
        // Try to authenticate with non-existent algorithm
        $authenticator = new Authenticator(['hashAlgorithm' => 123]);

        if (PHP_VERSION_ID >= 80000) {
            $this->expectException(\Error::class);
        } else {
            $this->expectException(\RuntimeException::class);
        }

        $authenticator->createPasswordHash($this->password);
    }
}
