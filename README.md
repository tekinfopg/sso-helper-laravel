# Keycloak SSO for Laravel

This package provides integration between Laravel and Keycloak, enabling Single Sign-On (SSO) and a convenient way to handle Keycloak tokens.

## Requirements

- PHP ^8.1
- Laravel ^8.0 || ^9.0 || ^10.0 || ^11.0 || ^12.0

## Installation

1. Require the package:
   ```bash
   composer require edoaurahman/keycloak-sso
   ```

2. Publish and configure the package:
   ```bash
   php artisan vendor:publish --provider="Edoaurahman\\KeycloakSso\\KeycloakServiceProvider" --tag=keycloak-config
   ```
   or
   ```bash
   php artisan vendor:publish --tag=keycloak-config
   ```
   This will publish a config file at `config/keycloak.php`. Adjust the settings to match your Keycloak realm, tokens, etc.

4. Set up the fields for storing tokens in your User model:
   ```php
   // in your database migration
   Schema::table('users', function (Blueprint $table) {
       $table->string('keycloak_token')->nullable();
       $table->string('keycloak_refresh_token')->nullable();
   });

   // in your User model
   protected $fillable = [
       // ...
       'keycloak_token',
       'keycloak_refresh_token',
   ];
   ```

## Usage

# KeycloakProviderService Interface

| Method                                      | Description                                                          | Parameters                              | Return Type  |
| ------------------------------------------- | -------------------------------------------------------------------- | --------------------------------------- | ------------ |
| `setBaseUrl($baseUrl)`                      | Set the base Keycloak URL.                                           | `string $baseUrl`                      | `void`       |
| `setRealm($realm)`                          | Set the Keycloak realm.                                              | `string $realm`                        | `void`       |
| `setTokenField($tokenField)`                | Set the custom token field.                                          | `string $tokenField`                   | `void`       |
| `setRefreshTokenField($refreshTokenField)`  | Set the custom refresh token field.                                  | `string $refreshTokenField`            | `void`       |
| `refreshToken($refreshToken = null)`        | Refresh the Keycloak access token.                                   | `string $refreshToken` (nullable)      | `string|null`|
| `request($method, $url, $data = [])`        | Generic request to Keycloak API.                                     | `string $method`, `string $url`, `array $data` | `array` |
| `getClientList()`                           | Get Keycloak client list.                                            | *N/A*                                  | `array`      |
| `getUserList()`                             | Get Keycloak user list.                                              | *N/A*                                  | `array`      |
| `getUser($id)`                              | Get a single user.                                                   | `string|int $id`                       | `array`      |
| `createUser($data)`                         | Create a new Keycloak user.                                          | `array $data`                          | `array`      |
| `updateUser($id, $data)`                    | Update an existing user.                                             | `string|int $id`, `array $data`        | `array`      |
| `deleteUser($id)`                           | Delete a user.                                                       | `string|int $id`                       | `array`      |
| `regenerateClientSecret($id)`               | Regenerate client’s secret.                                          | `string|int $id`                       | `array`      |
| `getUserRoles($id)`                         | Get roles assigned to a user.                                        | `string $id`                           | `array`      |
| `getRoles($clientUuid)`                     | Get all roles by client or realm.                                    | `string $clientUuid`                   | `array`      |
| `getUsersWithRole($roleName)`               | Get all users with a given role.                                     | `string $roleName`                     | `array`      |
| `getUsersWithRoles($clientUuid)`            | Get all users and their roles for a client.                         | `string $clientUuid`                   | `array`      |
| `createRole($clientUuid, $data)`            | Create a role for the realm or client.                              | `string $clientUuid`, `array $data`    | `array`      |
| `resetUserPassword($userId, $newPassword)`  | Reset the password of a user by ID.                                  | `string $userId`, `string $newPassword` | `array`      |
| `updateCurrentUserProfile($data)`           | Update the profile of the currently logged-in user.                 | `array $data`                          | `array`      |
| `deleteAllCurrentUserSessions()`            | Delete all sessions except the current session for the logged-in user. | *N/A*                                | `array`      |
| `deleteCurrentUserSessionById($sessionId)`  | Delete a session associated with the currently logged-in user by ID. | `string $sessionId`                    | `array`      |
| `sendVerificationEmail($userId)`            | Send a verification email to a user to verify their email address.  | `string $userId`                       | `array`      |
| `sendResetPasswordEmail($userId)`           | Send a reset password email to a user to reset their password.      | `string $userId`                       | `array`      |
| `Other method on progress`                  | -                                                                    | -                                       | -            |

## Example

```php
Route::get('/login-keycloak', function () {
    return Socialite::driver('keycloak')->redirect();
});

Route::get('/callback-keycloak', function () {
    $user = Socialite::driver('keycloak')->user();
    // Handle login logic...
});

Route::get('/get-users-keycloak', function (KeycloakProviderServiceInterface $keycloak) {
    return $keycloak->getUserList();
});
```

## Contributing

Contributions are welcome! Feel free to submit a pull request or open an issue.

## License

This package is open-sourced software licensed under the [MIT license](LICENSE.md).
