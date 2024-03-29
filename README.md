# Lockout Authenticator

[![Latest Stable Version](https://poser.pugx.org/andreasnij/lockout-authentication/v/stable)](https://packagist.org/packages/andreasnij/lockout-authentication)

This simple PHP authenticator uses the built-in PHP password hashing and verification functions to authenticate
user objects implementing the provided interface. It has a lockout mechanism preventing users from logging in for
a few seconds after they failed to login multiple times, making brute force attacks less effective.

## Installation
Add the package as a requirement to your `composer.json`:
```bash
$ composer require andreasnij/lockout-authenticator
```

## Usage
```php

use LockoutAuthentication\Authenticator;

$authenticator = new Authenticator();
if ($authenticator->authenticate($user, $_POST['password'])) {
    // Place code to login user here
    echo 'You are now logged in!';
} elseif ($authenticator->isLoginBlocked()) {
    echo 'Your account has temporarily been locked due to multiple '
        . 'failed login attempts. Try again later.';
} else {
    echo 'The username or password is incorrect!';
}

// Place code to save the $user object to persistent storage here
```


## Requirements
- Lockout Authenticator requires PHP 7.4 or above.

## Author
Andreas Nilsson <http://github.com/andreasnij>

## License
Lockout Authenticator is licensed under the MIT License - see the [LICENSE](LICENSE.md) file for details.
