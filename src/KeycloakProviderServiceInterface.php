<?php

namespace Edoaurahman\KeycloakSso;

interface KeycloakProviderServiceInterface
{
    /**
     * Refresh the access token using the refresh token
     * @param string $refreshToken
     * @return void
     */
    public function refreshToken($refreshToken = null): ?string;
}