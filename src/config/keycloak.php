<?php
return [
    'client_id' => env('KEYCLOAK_CLIENT_ID'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
    'redirect' => env('KEYCLOAK_REDIRECT_URI'),
    'base_url' => env('KEYCLOAK_BASE_URL'),         // Specify your keycloak server URL here
    'realms' => env('KEYCLOAK_REALM'),              // Specify your keycloak realm
    'token_field' => 'keycloak_token',                   // Specify the field name for storing the Keycloak token
    'refresh_token_field' => 'keycloak_refresh_token',   // Specify the field name for storing the Keycloak refresh token
];
