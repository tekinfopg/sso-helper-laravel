<?php
return [
    'client_id' => env('KEYCLOAK_CLIENT_ID'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
    'client_uuid' => env('KEYCLOAK_CLIENT_UUID'),
    'redirect' => env('KEYCLOAK_REDIRECT_URI'),
    'base_url' => env('KEYCLOAK_BASE_URL'),
    'realms' => env('KEYCLOAK_REALM'),
    'api_url' => env('KEYCLOAK_API_URL'),
    'token_field' => 'keycloak_token',
    'refresh_token_field' => 'keycloak_refresh_token',
    'session_access_token_field' => 'access_token',
    'session_refresh_token_field' => 'refresh_token',
    
    // HTTP timeout settings (in seconds)
    'timeout' => env('KEYCLOAK_TIMEOUT', 30),
    'connect_timeout' => env('KEYCLOAK_CONNECT_TIMEOUT', 10),
];
