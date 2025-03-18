# Keycloak SSO for Laravel

This package provides integration between Laravel and Keycloak, enabling Single Sign-On (SSO) and a convenient way to handle Keycloak tokens.

## Requirements

- PHP ^7.4 || ^8.1
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
   This will publish a config file at `config/keycloak.php`. Adjust the settings to match your Keycloak realm, tokens, etc.

3. Set up the fields for storing tokens in your User model:
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

- **KeycloakProviderService**  
  This class extends Laravel Socialite’s AbstractProvider, offering methods to grab tokens, refresh them, and interact with the Keycloak Admin API.

- **Retrieving the session token**  
  The access token is stored in Laravel’s session as `access_token`, and the refresh token as `refresh_token`.  
  For custom handling, you can override or extend methods within `KeycloakProviderService`.

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