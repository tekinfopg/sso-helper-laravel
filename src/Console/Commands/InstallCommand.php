<?php

namespace Edoaurahman\KeycloakSso\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;

class InstallCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'keycloak:install 
                            {--force : Overwrite existing files}
                            {--env : Update .env file}
                            {--all : Publish all files and update .env}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Install Keycloak SSO package with guided setup';

    /**
     * Execute the console command.
     */
    public function handle()
    {
        $this->info('🚀 Installing Keycloak SSO Package...');
        $this->newLine();

        // Check if --all flag is set
        $all = $this->option('all');

        // Step 1: Publish config file
        $this->publishConfig();

        // Step 2: Update services.php
        $this->updateServicesConfig();

        // Step 3: Add event listener based on Laravel version
        $this->addEventListener();

        // Step 4: Update .env file (if --env or --all flag is set or user confirms)
        if ($all || $this->option('env') || $this->confirm('Do you want to update .env file with Keycloak configuration?', true)) {
            $this->updateEnvFile();
        }

        // Step 5: Show migration instructions
        $this->showMigrationInstructions();

        $this->newLine();
        $this->info('✅ Keycloak SSO Package installed successfully!');
        $this->newLine();
        $this->line('Next steps:');
        $this->line('1. Run migrations: php artisan migrate');
        $this->line('2. Update your User model with the keycloak_token and keycloak_refresh_token fields');
        $this->line('3. Set up your routes for authentication');
        $this->newLine();

        return Command::SUCCESS;
    }

    /**
     * Publish the config file
     */
    protected function publishConfig()
    {
        $this->comment('📦 Publishing configuration file...');

        $configPath = config_path('keycloak.php');

        if (File::exists($configPath) && !$this->option('force')) {
            if (!$this->confirm('Config file already exists. Do you want to overwrite it?', false)) {
                $this->warn('⚠️  Skipped publishing config file.');
                return;
            }
        }

        $this->call('vendor:publish', [
            '--provider' => 'Edoaurahman\\KeycloakSso\\KeycloakServiceProvider',
            '--tag' => 'keycloak-config',
            '--force' => true,
        ]);

        $this->info('✓ Config file published successfully');
        $this->newLine();
    }

    /**
     * Update services.php config
     */
    protected function updateServicesConfig()
    {
        $this->comment('⚙️  Updating services configuration...');

        $servicesPath = config_path('services.php');

        if (!File::exists($servicesPath)) {
            $this->error('✗ services.php not found!');
            return;
        }

        $content = File::get($servicesPath);

        // Check if keycloak config already exists
        if (Str::contains($content, "'keycloak' =>")) {
            $this->warn('⚠️  Keycloak configuration already exists in services.php');
            return;
        }

        // Add keycloak config before the closing bracket
        $keycloakConfig = "\n    'keycloak' => [\n"
            . "        'client_id' => env('KEYCLOAK_CLIENT_ID'),\n"
            . "        'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),\n"
            . "        'redirect' => env('KEYCLOAK_REDIRECT_URI'),\n"
            . "        'base_url' => env('KEYCLOAK_BASE_URL'),\n"
            . "        'realms' => env('KEYCLOAK_REALM'),\n"
            . "    ],\n";

        // Find the last occurrence of ];
        $lastBracketPos = strrpos($content, '];');

        if ($lastBracketPos !== false) {
            $content = substr_replace($content, $keycloakConfig, $lastBracketPos, 0);
            File::put($servicesPath, $content);
            $this->info('✓ services.php updated successfully');
        } else {
            $this->error('✗ Could not find the closing bracket in services.php');
            $this->line('Please add the following configuration manually to config/services.php:');
            $this->line($keycloakConfig);
        }

        $this->newLine();
    }

    /**
     * Add event listener based on Laravel version
     */
    protected function addEventListener()
    {
        $this->comment('🎯 Setting up event listener...');

        $laravelVersion = (int) Str::before(app()->version(), '.');

        if ($laravelVersion >= 11) {
            $this->addLaravel11EventListener();
        } else {
            $this->addLegacyEventListener();
        }

        $this->newLine();
    }

    /**
     * Add event listener for Laravel 11+
     */
    protected function addLaravel11EventListener()
    {
        $this->line('Detected Laravel ' . app()->version() . ' (Laravel 11+)');

        $appServiceProviderPath = app_path('Providers/AppServiceProvider.php');

        if (!File::exists($appServiceProviderPath)) {
            $this->error('✗ AppServiceProvider.php not found!');
            $this->showManualInstructions(11);
            return;
        }

        $content = File::get($appServiceProviderPath);

        // Check if keycloak listener already exists
        if (Str::contains($content, 'SocialiteProviders\Manager\SocialiteWasCalled') 
            || Str::contains($content, 'SocialiteProviders\\\\Manager\\\\SocialiteWasCalled')) {
            $this->warn('⚠️  Event listener already exists in AppServiceProvider');
            return;
        }

        // Add use statements if not exists
        $useStatements = [];
        if (!Str::contains($content, 'use Illuminate\Support\Facades\Event;')) {
            $useStatements[] = 'use Illuminate\Support\Facades\Event;';
        }

        // Find the boot method
        if (!preg_match('/public function boot\(\)(?:\s*:\s*void)?\s*\{/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $this->error('✗ Could not find boot method in AppServiceProvider');
            $this->showManualInstructions(11);
            return;
        }

        $bootMethodPos = $matches[0][1] + strlen($matches[0][0]);

        // Event listener code
        $eventListenerCode = "\n        Event::listen(function (\\SocialiteProviders\\Manager\\SocialiteWasCalled \$event) {\n"
            . "            \$event->extendSocialite('keycloak', \\SocialiteProviders\\Keycloak\\Provider::class);\n"
            . "        });\n";

        // Insert use statements
        if (!empty($useStatements)) {
            $namespacePos = strpos($content, 'namespace');
            $semicolonPos = strpos($content, ';', $namespacePos);
            $insertPos = $semicolonPos + 1;
            
            $useStatementsString = "\n" . implode("\n", $useStatements);
            $content = substr_replace($content, $useStatementsString, $insertPos, 0);
            
            // Adjust boot method position
            $bootMethodPos += strlen($useStatementsString);
        }

        // Insert event listener in boot method
        $content = substr_replace($content, $eventListenerCode, $bootMethodPos, 0);

        File::put($appServiceProviderPath, $content);
        $this->info('✓ Event listener added to AppServiceProvider');
    }

    /**
     * Add event listener for Laravel 10 and below
     */
    protected function addLegacyEventListener()
    {
        $this->line('Detected Laravel ' . app()->version() . ' (Laravel 10 or below)');

        $eventServiceProviderPath = app_path('Providers/EventServiceProvider.php');

        if (!File::exists($eventServiceProviderPath)) {
            $this->error('✗ EventServiceProvider.php not found!');
            $this->showManualInstructions(10);
            return;
        }

        $content = File::get($eventServiceProviderPath);

        // Check if keycloak listener already exists
        if (Str::contains($content, 'SocialiteProviders\Keycloak\KeycloakExtendSocialite') 
            || Str::contains($content, 'SocialiteProviders\\\\Keycloak\\\\KeycloakExtendSocialite')) {
            $this->warn('⚠️  Event listener already exists in EventServiceProvider');
            return;
        }

        // Find the $listen array
        if (!preg_match('/protected\s+\$listen\s*=\s*\[/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $this->error('✗ Could not find $listen array in EventServiceProvider');
            $this->showManualInstructions(10);
            return;
        }

        $listenArrayPos = $matches[0][1] + strlen($matches[0][0]);

        // Event listener code
        $eventListenerCode = "\n        \\SocialiteProviders\\Manager\\SocialiteWasCalled::class => [\n"
            . "            \\SocialiteProviders\\Keycloak\\KeycloakExtendSocialite::class . '@handle',\n"
            . "        ],";

        // Insert event listener in $listen array
        $content = substr_replace($content, $eventListenerCode, $listenArrayPos, 0);

        File::put($eventServiceProviderPath, $content);
        $this->info('✓ Event listener added to EventServiceProvider');
    }

    /**
     * Show manual instructions for event listener
     */
    protected function showManualInstructions($version)
    {
        $this->warn('Please add the event listener manually:');
        $this->newLine();

        if ($version >= 11) {
            $this->line('In app/Providers/AppServiceProvider.php, add to the boot method:');
            $this->newLine();
            $this->line("use Illuminate\Support\Facades\Event;");
            $this->newLine();
            $this->line("Event::listen(function (\SocialiteProviders\Manager\SocialiteWasCalled \$event) {");
            $this->line("    \$event->extendSocialite('keycloak', \SocialiteProviders\Keycloak\Provider::class);");
            $this->line("});");
        } else {
            $this->line('In app/Providers/EventServiceProvider.php, add to the $listen array:');
            $this->newLine();
            $this->line("\SocialiteProviders\Manager\SocialiteWasCalled::class => [");
            $this->line("    \SocialiteProviders\Keycloak\KeycloakExtendSocialite::class . '@handle',");
            $this->line("],");
        }
    }

    /**
     * Update .env file
     */
    protected function updateEnvFile()
    {
        $this->comment('🔧 Updating .env file...');
        $this->newLine();

        $envPath = base_path('.env');

        if (!File::exists($envPath)) {
            $this->error('✗ .env file not found!');
            return;
        }

        $envContent = File::get($envPath);

        // Check if keycloak config already exists
        $hasKeycloakConfig = Str::contains($envContent, 'KEYCLOAK_CLIENT_ID');

        if ($hasKeycloakConfig) {
            if (!$this->confirm('Keycloak configuration already exists in .env. Do you want to update it?', false)) {
                $this->warn('⚠️  Skipped updating .env file');
                $this->newLine();
                return;
            }
        }

        // Gather configuration
        $config = [
            'KEYCLOAK_CLIENT_ID' => $this->ask('Keycloak Client ID', $this->getEnvValue($envContent, 'KEYCLOAK_CLIENT_ID', 'your-client-id')),
            'KEYCLOAK_CLIENT_SECRET' => $this->ask('Keycloak Client Secret', $this->getEnvValue($envContent, 'KEYCLOAK_CLIENT_SECRET', 'your-client-secret')),
            'KEYCLOAK_CLIENT_UUID' => $this->ask('Keycloak Client UUID', $this->getEnvValue($envContent, 'KEYCLOAK_CLIENT_UUID', 'your-client-uuid')),
            'KEYCLOAK_REDIRECT_URI' => $this->ask('Keycloak Redirect URI', $this->getEnvValue($envContent, 'KEYCLOAK_REDIRECT_URI', config('app.url') . '/callback-keycloak')),
            'KEYCLOAK_BASE_URL' => $this->ask('Keycloak Base URL', $this->getEnvValue($envContent, 'KEYCLOAK_BASE_URL', 'https://keycloak.example.com/')),
            'KEYCLOAK_REALM' => $this->ask('Keycloak Realm', $this->getEnvValue($envContent, 'KEYCLOAK_REALM', 'master')),
            'KEYCLOAK_API_URL' => $this->ask('Keycloak API URL', $this->getEnvValue($envContent, 'KEYCLOAK_API_URL', 'https://keycloak.example.com/')),
        ];

        // Update or append to .env
        foreach ($config as $key => $value) {
            $envContent = $this->updateEnvVariable($envContent, $key, $value);
        }

        File::put($envPath, $envContent);

        $this->info('✓ .env file updated successfully');
        $this->newLine();
    }

    /**
     * Get existing env value
     */
    protected function getEnvValue($content, $key, $default = '')
    {
        if (preg_match("/^{$key}=(.*)$/m", $content, $matches)) {
            return trim($matches[1]);
        }

        return $default;
    }

    /**
     * Update or add env variable
     */
    protected function updateEnvVariable($content, $key, $value)
    {
        // Escape special characters for regex
        $escapedKey = preg_quote($key, '/');

        // Check if key exists
        if (preg_match("/^{$escapedKey}=.*$/m", $content)) {
            // Update existing key
            $content = preg_replace("/^{$escapedKey}=.*$/m", "{$key}={$value}", $content);
        } else {
            // Append new key
            $content .= "\n{$key}={$value}";
        }

        return $content;
    }

    /**
     * Show migration instructions
     */
    protected function showMigrationInstructions()
    {
        $this->comment('📝 Database Migration Instructions:');
        $this->newLine();
        $this->line('Add the following to your users table migration:');
        $this->newLine();
        $this->line("Schema::table('users', function (Blueprint \$table) {");
        $this->line("    \$table->text('keycloak_token')->nullable();");
        $this->line("    \$table->text('keycloak_refresh_token')->nullable();");
        $this->line("});");
        $this->newLine();
        $this->line('And add to your User model $fillable:');
        $this->line("'keycloak_token', 'keycloak_refresh_token'");
        $this->newLine();
    }
}
