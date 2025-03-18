<?php

namespace Edoaurahman\KeycloakSso;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use GuzzleHttp\Exception\ClientException;
use Edoaurahman\KeycloakSso\KeycloakProviderServiceInterface;
use Carbon\Carbon;

class KeycloakProviderService extends AbstractProvider implements ProviderInterface, KeycloakProviderServiceInterface
{
    /**
     * The base URL for Keycloak.
     *
     * @var string
     */
    public $baseUrl;

    /**
     * The Keycloak realm.
     *
     * @var string
     */
    public $realm;

    /**
     * The field name for storing the Keycloak token.
     *
     * @var string
     */
    protected $tokenField;

    /**
     * The field name for storing the Keycloak refresh token.
     *
     * @var string
     */
    protected $refreshTokenField;

    /**
     * Create a new provider instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  string  $redirectUrl
     * @param  array  $guzzle
     * @return void
     */
    public function __construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle = [])
    {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle);

        $this->baseUrl = Config::get('keycloak.base_url');
        $this->realm = Config::get('keycloak.realms');
        $this->tokenField = Config::get('keycloak.token_field', 'keycloak_token');
        $this->refreshTokenField = Config::get('keycloak.refresh_token_field', 'keycloak_refresh_token');
    }

    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/auth",
            $state
        );
    }

    protected function getTokenUrl()
    {
        return "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/token";
    }

    protected function getUserByToken($token)
    {
        try {
            $response = $this->getHttpClient()->get(
                "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/userinfo",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
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
            $user = Auth::user();
            if (!$user || !isset($user->{$this->refreshTokenField})) {
                return null;
            }
            $refreshToken = $user->{$this->refreshTokenField};
            if (!$refreshToken) {
                return null;
            }
        } else if (!Auth::user() || !isset(Auth::user()->{$this->refreshTokenField})) {
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
            Session::put([
                'access_token' => $data['access_token'],
                'refresh_token' => $data['refresh_token'] ?? $refreshToken,
                'expires_in' => $data['expires_in'],
                'token_expiration' => Carbon::now()->addSeconds($data['expires_in'])->timestamp,
            ]);
            // update user's refresh token
            $user = Auth::user();
            if (method_exists($user, 'forceFill') && method_exists($user, 'save')) {
                $user->forceFill([
                    $this->tokenField => $data['access_token'],
                    $this->refreshTokenField => $data['refresh_token'] ?? $refreshToken,
                ])->save();
            }

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
     * @return mixed
     * @throws \Exception
     * 
     */
    public function request($method, $url, $data = []): array
    {
        $token = Session::get('access_token');
        if (!$token) {
            throw new \Exception('Access token not found');
        }

        try {
            $response = $this->getHttpClient()->request($method, $url, [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => "Bearer {$token}",
                ],
                'json' => $data,
            ]);

            $result = json_decode($response->getBody(), true);

            // Handle null response
            if ($result === null) {
                return [];
            }

            return $result;
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
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
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/clients");
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

    /**
     * get user list
     * 
     * @return array
     * @throws \Exception
     * 
     */
    public function getUserList(): array
    {
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/users");
    }

    /**
     * get user by id
     * 
     * @param string $id
     * @return array
     * @throws \Exception
     * 
     */
    public function getUser($id): array
    {
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/users/{$id}");
    }

    /**
     * create user
     * 
     * @param array $data
     * @return array
     * @throws \Exception
     * 
     */
    public function createUser($data): array
    {
        return $this->request('POST', "{$this->baseUrl}admin/realms/{$this->realm}/users", $data);
    }

    /**
     * update user
     * 
     * @param string $id
     * @param array $data
     * @return array
     * @throws \Exception
     * 
     */
    public function updateUser($id, $data): array
    {
        return $this->request('PUT', "{$this->baseUrl}admin/realms/{$this->realm}/users/{$id}", $data);
    }

    /**
     * delete user
     * 
     * @param string $id
     * @return array
     * @throws \Exception
     * 
     */
    public function deleteUser($id): array
    {
        return $this->request('DELETE', "{$this->baseUrl}admin/realms/{$this->realm}/users/{$id}");
    }

    /**
     * regenerate client secret
     * 
     * @param string $id
     * @return array
     * @throws \Exception
     * 
     */
    public function regenerateClientSecret($id): array
    {
        return $this->request('POST', "{$this->baseUrl}admin/realms/{$this->realm}/clients/{$id}/client-secret");
    }

    /**
     * Get Roles of a user
     * 
     * @param string $id
     * @return array
     * @throws \Exception
     * 
     */
    public function getUserRoles($id): array
    {
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/users/{$id}/role-mappings");
    }

    /**
     * Get all roles for the realm or client
     * 
     * @param string $clientUuid
     * @return array
     * @throws \Exception
     */

    public function getRoles($clientUuid): array
    {
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/clients/{$clientUuid}/roles");
    }

    /**
     * Get all users with a specific role
     * 
     * @param string $roleName
     * @return array
     * 
     */
    public function getUsersWithRole($roleName): array
    {
        return $this->request('GET', "{$this->baseUrl}admin/realms/{$this->realm}/roles/{$roleName}/users");
    }

    /**
     * Get all users with their roles
     * 
     * @param string $clientUuid
     * @return array
     * 
     */
    public function getUsersWithRoles($clientUuid): array
    {
        $users = $this->getUserList();
        $roles = $this->getRoles($clientUuid);
        $roleMappings = [];
        foreach ($roles as $role) {
            $roleMappings[$role['id']] = $role['name'];
        }

        foreach ($users as $key => $user) {
            $userRoles = $this->getUserRoles($user['id']);
            $users[$key]['roles'] = [];

            // Process client-specific roles for the requested client
            if (isset($userRoles['clientMappings'])) {
                foreach ($userRoles['clientMappings'] as $clientName => $mapping) {
                    if (isset($mapping['mappings'])) {
                        foreach ($mapping['mappings'] as $role) {
                            if (isset($roleMappings[$role['id']])) {
                                $users[$key]['roles'][] = $roleMappings[$role['id']];
                            }
                        }
                    }
                }
            }

            // Also include realm roles if needed
            if (isset($userRoles['realmMappings'])) {
                foreach ($userRoles['realmMappings'] as $role) {
                    $users[$key]['roles'][] = $role['name'] ?? '';
                }
            }
        }

        return $users;
    }
}