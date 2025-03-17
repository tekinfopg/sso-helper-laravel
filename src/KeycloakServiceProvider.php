<?php

namespace Edoaurahman\KeycloakSso;

use Illuminate\Support\ServiceProvider;

class KeycloakServiceProvider extends ServiceProvider
{
    /**
     * Register 
     */
    public function register(): void
    {
        $this->app->bind(KeycloakProviderServiceInterface::class, function ($app) {
            return new KeycloakProviderService(
                $app['request'],
                config('keycloak.client_id'),
                config('keycloak.client_secret'),
                config('keycloak.redirect'),
                config('keycloak.scopes', [])
            );
        });
    }

    /**
     * Bootstrap 
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/keycloak.php' => config_path('keycloak.php'),
        ], 'config');
    }
}