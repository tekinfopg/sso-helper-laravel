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
    public function request($method, $url, $data = []): array;
    public function getClientList(): array;
}