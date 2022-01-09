<?php
/**
 * Lockout authentication.
 *
 * @copyright Copyright (c) 2015 Andreas Nilsson
 * @license   MIT
 */

namespace LockoutAuthentication;

/**
 * Lockout authentication authenticates a user with a
 * lockout if after multiple failed attempts.
 */
class Authenticator
{
    /**
     * @const int
     */
    const DEFAULT_ATTEMPTS_BEFORE_LOCKOUT = 3;

    /**
     * @const int
     */
    const DEFAULT_LOCKOUT_CLEAR_TIME = 300;

    /**
     * @var string|int
     */
    protected $hashAlgorithm = PASSWORD_DEFAULT;

    /**
     * @var array
     */
    protected $hashOptions = [];

    /**
     * @var int
     */
    protected $attemptsBeforeLockout = self::DEFAULT_ATTEMPTS_BEFORE_LOCKOUT;

    /**
     * @var int
     */
    protected $lockoutClearTime = self::DEFAULT_LOCKOUT_CLEAR_TIME;

    /**
     * Constructor.
     *
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        if (isset($options['hashAlgorithm'])) {
            $this->hashAlgorithm = $options['hashAlgorithm'];
        }

        if (isset($options['hashOptions'])) {
            $this->hashOptions = $options['hashOptions'];
        }

        if (isset($options['attemptsBeforeLockout'])) {
            $this->attemptsBeforeLockout = $options['attemptsBeforeLockout'];
        }

        if (isset($options['lockoutClearTime'])) {
            $this->lockoutClearTime = $options['lockoutClearTime'];
        }
    }

    /**
     * Authenticate a user.
     *
     * @param AuthenticatableUserInterface $user
     * @param string $password
     * @return bool
     */
    public function authenticate(AuthenticatableUserInterface $user, $password)
    {
        if ($this->isLoginBlocked($user)) {
            return false;
        } elseif (password_verify($password, $user->getPasswordHash())) {
            // Rehash if hashing options changed
            if (password_needs_rehash($user->getPasswordHash(), $this->hashAlgorithm, $this->hashOptions)) {
                $newHash = $this->createPasswordHash($password);
                $user->setPasswordHash($newHash);
            }

            $this->clearLockout($user);

            return true;
        } else {
            if ($this->shouldLockoutBeCleared($user)) {
                $this->clearLockout($user);
            }

            $this->addFailedLoginAttempt($user);

            return false;
        }
    }

    /**
     * Clear a user's login lockout.
     *
     * @param AuthenticatableUserInterface $user
     */
    protected function clearLockout(AuthenticatableUserInterface $user)
    {
        $user->setLastFailedLoginAttemptTime(0);
        $user->setFailedLoginAttempts(0);
        $user->setLoginBlockedUntilTime(0);
    }

    /**
     * Check if a user's previously set lockout has timed out and should be cleared entirely.
     *
     * @param AuthenticatableUserInterface $user
     * @return bool
     */
    protected function shouldLockoutBeCleared(AuthenticatableUserInterface $user)
    {
        return (time() - $this->lockoutClearTime) > $user->getLastFailedLoginAttemptTime();
    }

    /**
     * Add a failed login attempt to a user's lockout data.
     *
     * @param AuthenticatableUserInterface $user
     */
    protected function addFailedLoginAttempt(AuthenticatableUserInterface $user)
    {
        // Update failed attempts info on this user
        $user->setLastFailedLoginAttemptTime(time());
        $user->setFailedLoginAttempts($user->getFailedLoginAttempts() + 1);

        // Prevent user from additional login attempts for some seconds, preventing brute force attacks
        if ($user->getFailedLoginAttempts() > $this->attemptsBeforeLockout) {
            $blockUntil = time() + random_int(2, 10);
            $user->setLoginBlockedUntilTime($blockUntil);
        }
    }

    /**
     * Check if a user is blocked from logging in.
     *
     * @param AuthenticatableUserInterface $user
     * @return bool
     */
    public function isLoginBlocked(AuthenticatableUserInterface $user)
    {
        return ($user->getLoginBlockedUntilTime() > time());
    }

    /**
     * Create a new password hash.
     *
     * @param string $password
     * @return string
     */
    public function createPasswordHash($password)
    {
        // Capture errors from password_hash()
        $hashError = '';
        $errorLevel = error_reporting(-1);
        set_error_handler(function ($errno, $errstr) use (&$hashError) {
            $hashError = $errstr;
        });

        $hash = password_hash($password, $this->hashAlgorithm, $this->hashOptions);

        restore_error_handler();
        error_reporting($errorLevel);

        if (!$hash) {
            throw new \RuntimeException("Password hashing failed: {$hashError}");
        }

        return $hash;
    }
}
