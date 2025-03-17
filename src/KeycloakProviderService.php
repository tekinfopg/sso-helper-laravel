<?php

namespace Edoaurahman\KeycloakSso;

use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use GuzzleHttp\Exception\ClientException;

class KeycloakProviderService extends AbstractProvider implements ProviderInterface, KeycloakProviderServiceInterface
{
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            config('keycloak.base_url') . 'realms/' . config('keycloak.realms') . '/protocol/openid-connect/auth',
            $state
        );
    }

    protected function getTokenUrl()
    {
        return config('keycloak.base_url') . 'realms/' . config('keycloak.realms') . '/protocol/openid-connect/token';
    }

    protected function getUserByToken($token)
    {
        try {
            $response = $this->getHttpClient()->get(
                config('keycloak.base_url') . 'realms/' . config('keycloak.realms') . '/protocol/openid-connect/userinfo',
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => 'Bearer ' . $token,
                    ],
                ]
            );

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(session('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getUserByToken($newToken);
                }
            }
            throw $e;
        }
    }

    /**
     * Refresh the access token using the refresh token
     *
     * @param string $refreshToken
     * @return string|null New access token or null if refresh failed
     */
    public function refreshToken($refreshToken = null): ?string
    {
        if (!$refreshToken) {
            $refreshToken = auth()->user()->keycloak_refresh_token;
            if (!$refreshToken) {
                return null;
            }
        } else if (!auth()->user()->keycloak_refresh_token) {
            return null;
        }

        try {
            $response = $this->getHttpClient()->post($this->getTokenUrl(), [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'refresh_token' => $refreshToken,
                    'client_id' => $this->clientId,
                    'client_secret' => $this->clientSecret,
                ],
            ]);

            $data = json_decode($response->getBody(), true);
            // Store the new tokens
            session([
                'access_token' => $data['access_token'],
                'refresh_token' => $data['refresh_token'] ?? $refreshToken,
                'expires_in' => $data['expires_in'],
                'token_expiration' => now()->addSeconds($data['expires_in'])->timestamp,
            ]);

            // update user's refresh token
            auth()->user()->update([
                'keycloak_token' => $data['access_token'],
                'keycloak_refresh_token' => $data['refresh_token'] ?? $refreshToken,
            ]);

            return $data['access_token'];
        } catch (\Exception $e) {
            // If refresh token is invalid or expired, redirect to login
            return null;
        }
    }

    /**
     * Function to handle request user, GET POST PUT DELETE etc
     * 
     * @param string $method
     * @param string $url
     * @param array $data
     * @return array
     * @throws \Exception
     * 
     */
    public function request($method, $url, $data = []): array
    {
        $token = session('access_token');
        if (!$token) {
            throw new \Exception('Access token not found');
        }

        try {
            $response = $this->getHttpClient()->request($method, $url, [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $token,
                ],
                'json' => $data,
            ]);

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(session('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->request($method, $url, $data);
                }
            }
            throw $e;
        }
    }

    /**
     * get client id list
     * 
     * @return array
     * @throws \Exception
     * 
     */
    public function getClientList(): array
    {
        return $this->request('GET', config('keycloak.base_url') . 'admin/realms/' . config('keycloak.realms') . '/clients');
    }


    /**
     * Map the raw user array to a Socialite User instance.
     *
     * @param  array  $user
     * @return \Laravel\Socialite\Two\User
     */
    protected function mapUserToObject(array $user)
    {
        return (new \Laravel\Socialite\Two\User)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['picture'] ?? null,
        ]);
    }
}