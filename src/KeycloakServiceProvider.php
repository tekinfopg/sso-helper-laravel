<?php

namespace Edoaurahman\KeycloakSso;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

class KeycloakServiceProvider extends ServiceProvider
{
    /**
     * Register 
     */
    public function register(): void
    {
        $this->app->bind(
            KeycloakProviderServiceInterface::class,
            fn($app) =>
            new KeycloakProviderService(
                $app['request'],
                Config::get('keycloak.client_id'),
                Config::get('keycloak.client_secret'),
                Config::get('keycloak.redirect'),
                Config::get('keycloak.scopes', []),
            )
        );
    }

    /**
     * Bootstrap 
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/config/keycloak.php' => $this->app->configPath('keycloak.php'),
        ], 'keycloak-config');
    }
}