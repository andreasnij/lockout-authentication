<?php
/**
 * Lockout authentication.
 *
 * @copyright Copyright (c) 2015 Andreas Nilsson
 * @license   MIT
 */

namespace LockoutAuthentication;

/**
 * @author Andreas Nilsson <http://github.com/jandreasn>
 */
interface AuthenticatableUserInterface
{
    /**
     * @param string $hash
     */
    public function setPasswordHash($hash);

    /**
     * @return string
     */
    public function getPasswordHash();

    /**
     * @param int $lastFailedLoginAttemptTime
     */
    public function setLastFailedLoginAttemptTime($lastFailedLoginAttemptTime);

    /**
     * @return int
     */
    public function getLastFailedLoginAttemptTime();

    /**
     * @param int $failedLoginAttempts
     */
    public function setFailedLoginAttempts($failedLoginAttempts);

    /**
     * @return int
     */
    public function getFailedLoginAttempts();

    /**
     * @param int $loginBlockedUntilTime
     */
    public function setLoginBlockedUntilTime($loginBlockedUntilTime);

    /**
     * @return int
     */
    public function getLoginBlockedUntilTime();
}
