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
        // publish config file
        $this->publishes([
            __DIR__ . '/config/keycloak.php' => $this->app->configPath('keycloak.php'),
        ], 'keycloak-config');

        // publish interface
        $this->publishes([
            __DIR__ . '/KeycloakProviderServiceInterface.php' => $this->app->basePath('app/Interfaces/KeycloakProviderServiceInterface.php'),
        ], 'keycloak-interface');

        // publish provider
        $this->publishes([
            __DIR__ . '/KeycloakProviderService.php' => $this->app->basePath('app/Providers/KeycloakProviderService.php'),
        ], 'keycloak-provider');

        // register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                \Edoaurahman\KeycloakSso\Console\Commands\InstallCommand::class,
            ]);
        }
    }
}