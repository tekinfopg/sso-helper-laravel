<?php

namespace Edoaurahman\KeycloakSso;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
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

    protected $tokenSessionKey;
    protected $refreshTokenSessionKey;

    /**
     * The unique identifier (UUID) of the Keycloak client.
     *
     * @var string
     */
    protected $clientUuid;

    /**
     * The identifier of the Keycloak client.
     *
     * @var string
     */
    protected $clientId;

    /**
     * Keycloak client secret used for authentication.
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * The base URL of the Keycloak API.
     *
     * @var string
     */
    protected $apiUrl;

    /**
     * Decode JWT token without verification
     * 
     * @param string $token
     * @return array
     * @throws \Exception
     */
    private function decodeJwt($token): array
    {
        if (empty($token)) {
            throw new \Exception('Token cannot be empty');
        }

        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new \Exception('Invalid JWT token format');
        }

        // Decode the payload (second part)
        $payload = $parts[1];

        // Add padding if needed
        $payload = str_pad($payload, strlen($payload) % 4, '=', STR_PAD_RIGHT);

        // Base64 decode
        $decoded = base64_decode(strtr($payload, '-_', '+/'));

        if ($decoded === false) {
            throw new \Exception('Failed to decode JWT payload');
        }

        // Parse JSON
        $data = json_decode($decoded, true);

        if ($data === null) {
            throw new \Exception('Failed to parse JWT payload as JSON');
        }

        return $data;
    }

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
        $this->tokenSessionKey = Config::get('keycloak.session_access_token_field', 'access_token');
        $this->refreshTokenSessionKey = Config::get('keycloak.session_refresh_token_field', 'refresh_token');
        $this->clientUuid = Config::get('keycloak.client_uuid');
        $this->clientId = Config::get('keycloak.client_id');
        $this->clientSecret = Config::get('keycloak.client_secret');
        $this->apiUrl = Config::get('keycloak.api_url');
    }


    /**
     * Set the base URL for Keycloak.
     *
     * @param string $baseUrl
     * @return void
     */
    public function setBaseUrl($baseUrl): void
    {
        $this->baseUrl = $baseUrl;
    }

    /**
     * set realm
     * @param string $realm
     * @return void
     */
    public function setRealm($realm): void
    {
        $this->realm = $realm;
    }

    /**
     * Set the token field name.
     *
     * @param string $tokenField
     * @return void
     */
    public function setTokenField($tokenField): void
    {
        $this->tokenField = $tokenField;
    }

    /**
     * Set the refresh token field name.
     *
     * @param string $refreshTokenField
     * @return void
     */
    public function setRefreshTokenField($refreshTokenField): void
    {
        $this->refreshTokenField = $refreshTokenField;
    }

    /**
     * Get the base URL for Keycloak.
     *
     * @return string
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase(
            "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/auth",
            $state
        );
    }

    /**
     * Get the access token URL for Keycloak.
     *
     * @return string
     */
    protected function getTokenUrl()
    {
        return "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/token";
    }

    /**
     * Get the user by token
     *
     * @param string $token
     * @return array
     * @throws \Exception
     */
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
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
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
            // First try to get refresh token from session
            $refreshToken = Session::get($this->refreshTokenSessionKey);

            // If not found in session, try to get from user model
            if (!$refreshToken) {
                $user = Auth::user();
                if ($user && isset($user->{$this->refreshTokenField})) {
                    $refreshToken = $user->{$this->refreshTokenField};
                }
            }

            // If still no refresh token found, return null
            if (!$refreshToken) {
                return null;
            }
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
                $this->tokenSessionKey => $data['access_token'],
                $this->refreshTokenSessionKey => $data['refresh_token'] ?? $refreshToken,
                'expires_in' => $data['expires_in'],
                'token_expiration' => Carbon::now()->addSeconds($data['expires_in'])->timestamp,
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
     * @return mixed
     * @throws \Exception
     * 
     */
    public function request($method, $url, $data = []): array
    {
        // Get token from session or user model
        $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        // Try to refresh if no token is found
        if (!$token && !($token = $this->refreshToken(Session::get($this->refreshTokenSessionKey)))) {
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
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
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
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/clients");
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
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/users");
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
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/users/{$id}");
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
        return $this->request('POST', "{$this->apiUrl}admin/realms/{$this->realm}/users", $data);
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
        return $this->request('PUT', "{$this->apiUrl}admin/realms/{$this->realm}/users/{$id}", $data);
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
        return $this->request('DELETE', "{$this->apiUrl}admin/realms/{$this->realm}/users/{$id}");
    }

    /**
     * regenerate client secret
     * 
     * @return array
     * @throws \Exception
     * 
     */
    public function regenerateClientSecret(): array
    {
        return $this->request('POST', "{$this->apiUrl}admin/realms/{$this->realm}/clients/{$this->clientUuid}/client-secret");
    }

    /**
     * Get Roles of a user
     * 
     * @param string $userUuid
     * @return array
     * @throws \Exception
     * 
     */
    public function getUserRoles($userUuid): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings");
    }

    /**
     * Get all roles for the client
     * 
     * @return array
     * @throws \Exception
     */

    public function getClientRoles(): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/clients/{$this->clientUuid}/roles");
    }

    /**
     * Get all users with a specific realm role
     * 
     * @param string $roleName
     * @return array
     * 
     */
    public function getUsersWithRole($roleName): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/roles/{$roleName}/users");
    }

    /**
     * Get all users with their roles
     * 
     * @return array
     * 
     */
    public function getUsersWithRoles(): array
    {
        $users = $this->getUserList();
        $roles = $this->getClientRoles();
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

    /**
     * Create a new role for the realm or client
     * 
     * @param array $data
     * @return array
     * 
     */
    public function createRole($data): array
    {
        try {
            $response = $this->getHttpClient()->post(
                "{$this->apiUrl}admin/realms/{$this->realm}/roles",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/json',
                    ],
                    'json' => $data,
                ]
            );

            if ($response->getStatusCode() === 201) {
                return [
                    'success' => true,
                    'message' => 'Role has been successfully created.',
                ];
            }
            return json_decode($response->getBody(), true);
        } catch (\Throwable $th) {
            throw $th;
        }
    }

    /**
     * Get Client UUID by client ID
     * 
     * @param string $clientId
     * @return string
     * 
     */
    public function getClientUuid($clientId): string
    {
        $clients = $this->getClientList();
        foreach ($clients as $client) {
            if ($client['clientId'] === $clientId) {
                return $client['id'];
            }
        }
        return '';
    }

    /**
     * Retrieves a list of user sessions associated with the Keycloak client.
     * 
     * @return array
     * 
     */
    public function getClientSessions(): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/clients/{$this->clientUuid}/user-sessions");
    }

    /**
     * Get client session stats Returns a JSON map.
     * 
     * @param string $clientUuid
     * @return array
     * 
     */
    public function getClientSessionStats(): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/client-session-stats");
    }

    /**
     * Get sessions associated with the user
     * 
     * @param string $userUuid
     * @return array
     */
    public function getUserSessionsByUserId($userUuid): array
    {
        return $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/sessions");
    }

    /**
     * Retrieves the session details of the currently logged-in user.
     *
     * @return array
     * An array containing details of each session.
     * 
     */
    public function getCurrentUserSessions(): array
    {
        try {// Get token from session or user model
            $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

            $response = $this->getHttpClient()->get(
                "{$this->baseUrl}realms/{$this->realm}/account/sessions/devices",
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
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getCurrentUserSessions();
                }
            }
            throw $e;
        }
    }

    /**
     * Retrieves the list of clients associated with the currently logged-in user.
     * 
     * @return array
     * An array containing details of each client.
     * 
     */
    public function getCurrentUserClients(): array
    {
        // Get token from session or user model
        $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->get(
                "{$this->baseUrl}realms/{$this->realm}/account/applications",
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
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getCurrentUserClients();
                }
            }
            throw $e;
        }
    }

    /**
     * Retrieves the authentication credentials associated with the currently logged-in user.
     *
     * @return array
     * An array containing details of user credentials.
     * 
     */
    public function getCurrentUserCredentials(): array
    {
        // Get token from session or user model
        $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->get(
                "{$this->baseUrl}realms/{$this->realm}/account/credentials",
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
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getCurrentUserCredentials();
                }
            }
            throw $e;
        }
    }

    public function deleteCurrentUserCredentialsById($credentialUuid): array
    {
        $token = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->delete(
                "{$this->baseUrl}realms/{$this->realm}/account/credentials/{$credentialUuid}",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            if ($response->getStatusCode() === 204) {
                return [
                    'success' => true,
                    'message' => 'Credentials deleted successfully.',
                ];
            }

            if ($response->getStatusCode() === 403) {
                return [
                    'success' => false,
                    'message' => 'Forbidden.',
                ];
            }

            if ($response->getStatusCode() === 404) {
                return [
                    'success' => false,
                    'message' => 'Credentials not found.',
                ];
            }

            return [
                'success' => false,
                'message' => 'Unable to delete user credentials. Please try again later or contact support.',
            ];
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->deleteCurrentUserCredentialsById($credentialUuid);
                }
            }

            throw $e;
        }
    }

    /**
     * Retrieves the profile information of the currently logged-in user.
     * 
     * @return array
     * An array containing user profile details.
     *
     */
    public function getCurrentUserProfile(): array
    {
        // Get token from session or user model
        $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $url = "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/userinfo";
            $response = $this->getHttpClient()->get(
                $url,
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            $response = json_decode($response->getBody(), true);

            $profile = [
                'id' => $response['sub'] ?? null,
                'username' => $response['preferred_username'] ?? null,
                'firstName' => $response['given_name'] ?? null,
                'lastName' => $response['family_name'] ?? null,
                'email' => $response['email'] ?? null,
                'emailVerified' => $response['email_verified'] ?? null,
                'phoneNumber' => $response['phoneNumber'] ?? null,
                'nik' => $response['nik'] ?? null,
                'department' => $response['department'] ?? null,
            ];

            return $profile;
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getCurrentUserProfile();
                }
            }
            throw $e;
        }
    }

    /**
     * Retrieves the groups associated with the currently logged-in user.
     * 
     * @return array
     * An array containing names of each group.
     * 
     */
    public function getCurrentUserGroups(): array
    {
        // Get token from session or user model
        $token = Session::get($this->tokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->get(
                "{$this->baseUrl}realms/{$this->realm}/account/groups",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            $response = json_decode($response->getBody(), true);

            $groups = [];

            if (!is_array($response) || empty($response)) {
                return $groups;
            }

            foreach ($response as $group) {
                $groups[] = $group['name'];
            }

            return $groups;
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get($this->refreshTokenSessionKey));
                if ($newToken) {
                    // Retry with the new token
                    return $this->getCurrentUserGroups();
                }
            }
            throw $e;
        }
    }

    /**
     * Reset the password of a user by ID.
     * 
     * @param string $userUuid
     * @param string $newPassword
     * @return array
     * An array containing the response data.
     * 
     */
    public function resetUserPassword($userUuid, $newPassword): array
    {
        $maxRetries = 3;
        $attempt = 0;

        while ($attempt < $maxRetries) {
            try {
                $response = $this->getHttpClient()->put(
                    "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/reset-password",
                    [
                        'headers' => [
                            'Accept' => 'application/json',
                            'Content-Type' => 'application/json',
                        ],
                        'json' => [
                            "type" => "password",
                            "temporary" => false,
                            "value" => $newPassword,
                        ],
                    ]
                );

                if ($response->getStatusCode() === 204) {
                    return [
                        'success' => true,
                        'message' => 'Password has been successfully updated.',
                    ];
                }

                return [
                    'success' => false,
                    'message' => 'Failed to update password. Please try again later or contact support.',
                ];
            } catch (ClientException $e) {
                if ($e->getResponse()->getStatusCode() === 404) {
                    $attempt++;
                    sleep(1);
                    continue;
                }

                throw $e;
            }
        }

        return [
            'success' => false,
            'message' => 'User does not exist. Please verify your details or create a new account.',
        ];
    }

    /**
     * Update the profile of the currently logged-in user.
     * 
     * @param array $data
     * @return array
     * An array containing the response data.
     * 
     */
    public function updateCurrentUserProfile($data): array
    {
        // Get token from session or user model
        $token = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->post(
                "{$this->baseUrl}realms/{$this->realm}/account",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                    'json' => $data
                ]
            );

            if ($response->getStatusCode() === 204) {
                return [
                    'success' => true,
                    'message' => 'User profile has been successfully updated.',
                ];
            }

            return [
                'success' => false,
                'message' => 'Failed to update user profile. Please try again later or contact support.',
            ];
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->updateCurrentUserProfile($data);
                }
            } else if ($e->getResponse()->getStatusCode() === 400) {
                return [
                    'success' => false,
                    'message' => 'A required user attribute is missing. Please check your input and try again.',
                ];
            }

            throw $e;
        }
    }

    /**
     * Delete all sessions except current session associated with the currently logged-in user.
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function deleteAllCurrentUserSessions(): array
    {
        // Get token from session or user model
        $token = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->delete(
                "{$this->baseUrl}realms/{$this->realm}/account/sessions",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            if ($response->getStatusCode() === 204) {
                return [
                    'success' => true,
                    'message' => 'Sessions deleted successfully.',
                ];
            }

            return [
                'success' => false,
                'message' => 'Unable to delete user sessions. Please try again later or contact support.',
            ];
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->deleteAllCurrentUserSessions();
                }
            }

            throw $e;
        }
    }

    /**
     * Delete a session associated with the currently logged-in user by ID.
     * 
     * @param string $sessionUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function deleteCurrentUserSessionById($sessionUuid): array
    {
        // Get token from session or user model
        $token = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        try {
            $response = $this->getHttpClient()->delete(
                "{$this->baseUrl}realms/{$this->realm}/account/sessions/{$sessionUuid}",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer {$token}",
                    ],
                ]
            );

            if ($response->getStatusCode() === 204) {
                return [
                    'success' => true,
                    'message' => 'Session deleted successfully.',
                ];
            }

            return [
                'success' => false,
                'message' => 'Unable to delete user session. Please try again later or contact support.',
            ];
        } catch (ClientException $e) {
            // Check if token expired (401 Unauthorized)
            if ($e->getResponse()->getStatusCode() === 401) {
                // Try to refresh the token
                $newToken = $this->refreshToken(Session::get('refresh_token'));
                if ($newToken) {
                    // Retry with the new token
                    return $this->deleteCurrentUserSessionById($sessionUuid);
                }
            }

            throw $e;
        }
    }

    /**
     * Send a verification email to a user to verify their email address.
     * 
     * @param string $userUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function sendVerificationEmail($userUuid): array
    {
        $maxRetries = 3;
        $attempt = 0;

        while ($attempt < $maxRetries) {
            try {
                $response = $this->getHttpClient()->put(
                    "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/send-verify-email",
                    [
                        'headers' => [
                            'Accept' => 'application/json',
                        ],
                    ]
                );

                if ($response->getStatusCode() === 204) {
                    return [
                        'success' => true,
                        'message' => 'Verification email has been sent successfully.',
                    ];
                }

                return [
                    'success' => false,
                    'message' => 'Failed to send verification email. Please try again later.',
                ];
            } catch (ClientException $e) {
                if ($e->getResponse()->getStatusCode() === 404) {
                    $attempt++;
                    sleep(1);
                    continue;
                }

                throw $e;
            }
        }

        return [
            'success' => false,
            'message' => 'User does not exist. Please verify your details or create a new account.',
        ];
    }

    /**
     * Send a reset password email to a user to reset their password.
     * 
     * @param string $userUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function sendResetPasswordEmail($userUuid): array
    {
        $maxRetries = 3;
        $attempt = 0;

        while ($attempt < $maxRetries) {
            try {
                $response = $this->getHttpClient()->put(
                    "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/reset-password-email",
                    [
                        'headers' => [
                            'Accept' => 'application/json',
                        ],
                    ]
                );

                if ($response->getStatusCode() === 204) {
                    return [
                        'success' => true,
                        'message' => 'Reset password email has been sent successfully.',
                    ];
                }

                return [
                    'success' => false,
                    'message' => 'Failed to send reset password email. Please try again later.',
                ];
            } catch (ClientException $e) {
                if ($e->getResponse()->getStatusCode() === 404) {
                    $attempt++;
                    sleep(1);
                    continue;
                }

                throw $e;
            }
        }

        return [
            'success' => false,
            'message' => 'User does not exist. Please verify your details or create a new account.',
        ];
    }

    /**
     * Check if the access token is expired
     * 
     * @return bool
     * 
     */
    public function isTokenExpired(): bool
    {
        $token = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

        // No token found, consider it expired
        if (!$token) {
            return true;
        }

        // First, check expiration time from JWT payload
        try {
            $decodedToken = $this->decodeJwt($token);
            $expiration = $decodedToken['exp'] ?? 0;

            // If token is expired based on exp claim, try to refresh it first
            if ($expiration > 0 && time() >= $expiration) {
                Log::debug('Token expired based on exp claim, attempting to refresh');

                // Try to refresh the token
                $refreshToken = Session::get($this->refreshTokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->refreshTokenField} : null);
                if ($refreshToken) {
                    $newToken = $this->refreshToken($refreshToken);
                    if ($newToken) {
                        Log::info('Token successfully refreshed');
                        return false; // Token is now valid after refresh
                    } else {
                        Log::warning('Failed to refresh expired token');
                        return true; // Refresh failed, token is expired
                    }
                } else {
                    Log::warning('No refresh token available for expired access token');
                    return true; // No refresh token, consider expired
                }
            }
        } catch (\Exception $e) {
            Log::warning('Failed to decode JWT token: ' . $e->getMessage());
            // If we can't decode the token, consider it expired
            return true;
        }

        // Retry mechanism for introspection
        $maxRetries = 3;
        $attempt = 0;

        while ($attempt < $maxRetries) {
            try {
                // Get the current token (might have been refreshed above)
                $currentToken = Session::get('access_token') ?? (Auth::user() ? Auth::user()->{$this->tokenField} : null);

                $response = $this->getHttpClient()->post(
                    "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/token/introspect",
                    [
                        'headers' => [
                            'Accept' => 'application/json',
                            'Content-Type' => 'application/x-www-form-urlencoded',
                        ],
                        'form_params' => [
                            'client_id' => $this->clientId,
                            'client_secret' => $this->clientSecret,
                            'token' => $currentToken,
                        ],
                        'timeout' => 30, // Add timeout
                        'connect_timeout' => 10, // Add connection timeout
                    ]
                );

                $responseData = json_decode($response->getBody(), true);
                $isExpired = !($responseData['active'] ?? false);

                // If token is expired according to introspection, try to refresh
                if ($isExpired) {
                    Log::debug('Token expired according to introspection, attempting to refresh');

                    $refreshToken = Session::get($this->refreshTokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->refreshTokenField} : null);
                    if ($refreshToken) {
                        $newToken = $this->refreshToken($refreshToken);
                        if ($newToken) {
                            Log::info('Token successfully refreshed after introspection');
                            return false; // Token is now valid after refresh
                        } else {
                            Log::warning('Failed to refresh token after introspection');
                            return true; // Refresh failed, token is expired
                        }
                    } else {
                        Log::warning('No refresh token available after introspection');
                        return true; // No refresh token, consider expired
                    }
                }

                return $isExpired;

            } catch (ClientException $e) {
                $attempt++;
                Log::warning("Token introspection attempt {$attempt} failed: " . $e->getMessage());

                // If it's the last attempt, check the error type
                if ($attempt >= $maxRetries) {
                    $statusCode = $e->getResponse() ? $e->getResponse()->getStatusCode() : 0;

                    // If it's a 401 (Unauthorized), try to refresh the token
                    if ($statusCode === 401) {
                        Log::info('Token introspection returned 401, attempting to refresh token');

                        $refreshToken = Session::get($this->refreshTokenSessionKey) ?? (Auth::user() ? Auth::user()->{$this->refreshTokenField} : null);
                        if ($refreshToken) {
                            $newToken = $this->refreshToken($refreshToken);
                            if ($newToken) {
                                Log::info('Token successfully refreshed after 401 error');
                                return false; // Token is now valid after refresh
                            } else {
                                Log::warning('Failed to refresh token after 401 error');
                                return true; // Refresh failed, token is expired
                            }
                        } else {
                            Log::warning('No refresh token available after 401 error');
                            return true; // No refresh token, consider expired
                        }
                    }

                    // For other errors (network issues, server errors, etc.), 
                    // and token is not expired based on JWT exp claim, return false
                    Log::error("All introspection attempts failed with status {$statusCode}, but token not expired based on exp claim");
                    return false;
                }

                // Wait before retry (exponential backoff)
                sleep(pow(2, $attempt - 1));

            } catch (\Exception $e) {
                $attempt++;
                Log::warning("Token introspection attempt {$attempt} failed with exception: " . $e->getMessage());

                // If it's the last attempt and not a client exception
                if ($attempt >= $maxRetries) {
                    // For network errors, curl errors, etc., if token is not expired 
                    // based on JWT exp claim, return false
                    Log::error("All introspection attempts failed with exception, but token not expired based on exp claim");
                    return false;
                }

                // Wait before retry (exponential backoff)
                sleep(pow(2, $attempt - 1));
            }
        }

        // This should never be reached, but just in case
        Log::error('Unexpected end of isTokenExpired method');
        return false;
    }

    /**
     * Retrieves the Keycloak client roles assigned to a specific user.
     * @param string $userUuid
     * @param bool $includeCompositeRole
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function getUserClientRoles($userUuid, bool $includeCompositeRole = false): array
    {
        $clientRoles = [];

        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings/clients/{$this->clientUuid}",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            $response = json_decode($response->getBody(), true);
            if ($includeCompositeRole) {
                $responseComposite = $this->getHttpClient()->get(
                    "{$this->apiUrl}admin/realms/{$this->realm}/ui-ext/effective-roles/users/{$userUuid}?first=0&max=-1",
                    [
                        'headers' => [
                            'Accept' => 'application/json',
                        ],
                    ]
                );
                $responseComposite = json_decode($responseComposite->getBody(), true);
                $responseComposite = collect($responseComposite)->where('client', operator: $this->clientId)->values()->toArray();
                foreach ($responseComposite as $role) {
                    $clientRoles[] = [
                        'name' => $role['role'],
                        'clientId' => $role['id']
                    ];
                }
            }
            foreach ($response as $role) {
                if ($role['name'] !== 'uma_protection') {
                    $clientRoles[] = [
                        'name' => $role['name'],
                        'clientId' => $role['id']
                    ];
                }
            }
            // remove duplicate
            $clientRoles = array_unique($clientRoles, SORT_REGULAR);
            return $clientRoles;
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Retrieves a list of users assigned to a specific client role.
     * 
     * @param string $roleName
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function getUsersByClientRole($roleName): array
    {
        $users = [];

        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/clients/{$this->clientUuid}/roles/{$roleName}/users",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            $response = json_decode($response->getBody(), true);

            if (empty($response)) {
                return $users;
            }

            foreach ($response as $user) {
                $users[] = [
                    'id' => $user['id'],
                    'username' => $user['username'],
                    'firstName' => $user['firstName'] ?? null,
                    'lastName' => $user['lastName'] ?? null,
                    'email' => $user['email'] ?? null,
                    'emailVerified' => $user['emailVerified'],
                    'phoneNumber' => isset($user['attributes']) ?
                        ($user['attributes']['phoneNumber'] ?? $user['attributes']['PhoneNumber'] ?? null)
                        : null,
                    'enabled' => $user['enabled'],
                ];
            }

            return $users;
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Get user roles by ID, in client
     * 
     * @param string $userUuid
     * @return array
     * An array containing the user roles.
     * 
     */
    public function getUserClientRolesById($userUuid): array
    {
        $clientRoles = [];

        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            $response = json_decode($response->getBody(), true);

            $roles = $response['clientMappings'][$this->clientId]['mappings'] ?? [];

            if (empty($roles)) {
                return $clientRoles;
            }
            foreach ($roles as $role) {
                if ($role['name'] !== 'uma_protection') {
                    $clientRoles[] = [
                        'name' => $role['name'],
                        'clientId' => $role['id']
                    ];
                }
            }

            return $clientRoles;
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Keycloak introspect token
     * 
     * @param string $token
     * @return array
     * An array containing the token introspection data.
     * 
     */
    public function introspectToken($token): array
    {
        try {
            $response = $this->getHttpClient()->post(
                "{$this->baseUrl}realms/{$this->realm}/protocol/openid-connect/token/introspect",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Content-Type' => 'application/x-www-form-urlencoded',
                    ],
                    'form_params' => [
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                        'token' => $token,
                    ],
                ]
            );

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Get events from Keycloak
     * 
     * @return array
     * An array containing the events data.
     * 
     */
    public function getKeycloakEvents(): array
    {
        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/events",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Get user events from Keycloak
     * 
     * @param string $userUuid
     * @return array
     */
    public function getUserEvents($userUuid): array
    {
        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/events",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                    ],
                ]
            );

            return json_decode($response->getBody(), true);
        } catch (ClientException $e) {
            throw $e;
        }
    }

    /**
     * Custom login redirect
     * 
     * @param string $redirectUri
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @param string|null $realm
     * @return string
     * A string containing the redirect URI.
     */
    public function getCustomLoginRedirect($redirectUri, $clientId = null, $clientSecret = null, $realm = null): string
    {
        $redirectUri = urlencode($redirectUri);
        $clientId = $clientId ?? urlencode($this->clientId);
        $clientSecret = $clientSecret ?? urlencode($this->clientSecret);
        $realm = $realm ?? urlencode($this->realm);
        $url = "{$this->baseUrl}realms/{$realm}/protocol/openid-connect/auth?client_id={$clientId}&client_secret={$clientSecret}&redirect_uri={$redirectUri}&response_type=code&scope=openid";
        return $url;
    }

    /**
     * Custom logout redirect
     * 
     * @param string $redirectUri
     * @param string|null $clientId
     * @param string|null $clientSecret
     * @param string|null $realm
     * @return string
     * A string containing the redirect URI.
     */
    public function getCustomLogoutRedirect($redirectUri, $clientId = null, $clientSecret = null, $realm = null): string
    {
        $redirectUri = urlencode($redirectUri);
        $clientId = $clientId ?? urlencode($this->clientId);
        $clientSecret = $clientSecret ?? urlencode($this->clientSecret);
        $realm = $realm ?? urlencode($this->realm);
        $url = "{$this->baseUrl}realms/{$realm}/protocol/openid-connect/logout?client_id={$clientId}&client_secret={$clientSecret}&redirect_uri={$redirectUri}";
        return $url;
    }

    /**
     * Get user by username
     * 
     * @param string $username
     * @return array
     * An array containing user data.
     */
    public function getUserByUsername($username): array
    {
        try {
            $response = $this->getHttpClient()->get(
                "{$this->apiUrl}admin/realms/{$this->realm}/users",
                [
                    'headers' => [
                        'Accept' => 'application/json',
                        'Authorization' => "Bearer " . (Session::get($this->tokenSessionKey) ?? Auth::user()->{$this->tokenField}),
                    ],
                    'query' => [
                        'username' => $username,
                        'exact' => true
                    ]
                ]
            );

            $response = json_decode($response->getBody(), true);

            if (empty($response)) {
                throw new \Exception("User with username '{$username}' not found");
            }

            return $response[0];
        } catch (\Exception $e) {
            throw new \Exception("Failed to get user by username: " . $e->getMessage());
        }
    }

    /**
     * Get client role by name
     * 
     * @param string $roleName
     * @return array
     * An array containing role data.
     */
    public function getClientRoleByName($roleName): array
    {
        try {
            $response = $this->request('GET', "{$this->apiUrl}admin/realms/{$this->realm}/clients/{$this->clientUuid}/roles/{$roleName}");
            return $response;
        } catch (\Exception $e) {
            throw new \Exception("Failed to get client role '{$roleName}': " . $e->getMessage());
        }
    }

    /**
     * Assign client role to user by username
     * 
     * @param string $username
     * @param string $roleName
     * @return array
     * An array containing the response data.
     */
    public function assignClientRoleToUser($username, $roleName): array
    {
        try {
            // Get user by username
            $user = $this->getUserByUsername($username);
            $userUuid = $user['id'];

            // Get role by name
            $role = $this->getClientRoleByName($roleName);

            // Check if user already has this role
            $currentRoles = $this->getUserClientRolesById($userUuid);
            foreach ($currentRoles as $currentRole) {
                if ($currentRole['name'] === $roleName) {
                    return [
                        'success' => true,
                        'message' => "Role '{$roleName}' is already assigned to user '{$username}'.",
                        'user_id' => $userUuid,
                        'role_name' => $roleName
                    ];
                }
            }

            // Format the role data properly for Keycloak API
            $roleData = [
                [
                    'id' => $role['id'],
                    'name' => $role['name'],
                    'clientRole' => true,
                    'containerId' => $this->clientUuid
                ]
            ];

            // Assign role to user
            $response = $this->request(
                'POST',
                "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings/clients/{$this->clientUuid}",
                $roleData
            );

            return [
                'success' => true,
                'message' => "Role '{$roleName}' has been successfully assigned to user '{$username}'.",
                'user_id' => $userUuid,
                'role_name' => $roleName,
                'role_data' => $role
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => "Failed to assign role '{$roleName}' to user '{$username}': " . $e->getMessage(),
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Remove client role from user by username
     * 
     * @param string $username
     * @param string $roleName
     * @return array
     * An array containing the response data.
     */
    public function removeClientRoleFromUser($username, $roleName): array
    {
        try {
            // Get user by username
            $user = $this->getUserByUsername($username);
            $userUuid = $user['id'];

            // Get role by name
            $role = $this->getClientRoleByName($roleName);

            // Check if user has this role
            $currentRoles = $this->getUserClientRolesById($userUuid);
            $hasRole = false;
            foreach ($currentRoles as $currentRole) {
                if ($currentRole['name'] === $roleName) {
                    $hasRole = true;
                    break;
                }
            }

            if (!$hasRole) {
                return [
                    'success' => true,
                    'message' => "Role '{$roleName}' is not assigned to user '{$username}'.",
                    'user_id' => $userUuid,
                    'role_name' => $roleName
                ];
            }

            // Format the role data properly for Keycloak API
            $roleData = [
                [
                    'id' => $role['id'],
                    'name' => $role['name'],
                    'clientRole' => true,
                    'containerId' => $this->clientUuid
                ]
            ];

            // Remove role from user
            $response = $this->request(
                'DELETE',
                "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings/clients/{$this->clientUuid}",
                $roleData
            );

            return [
                'success' => true,
                'message' => "Role '{$roleName}' has been successfully removed from user '{$username}'.",
                'user_id' => $userUuid,
                'role_name' => $roleName,
                'role_data' => $role
            ];
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => "Failed to remove role '{$roleName}' from user '{$username}': " . $e->getMessage(),
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Sync multiple roles for a user by username
     * 
     * @param string $username
     * @param array $roleNames
     * @param bool $replaceExisting
     * @return array
     * An array containing the response data.
     */
    public function syncUserClientRoles($username, array $roleNames, bool $replaceExisting = false): array
    {
        try {
            // Get user by username
            $user = $this->getUserByUsername($username);
            $userUuid = $user['id'];

            $results = [
                'success' => true,
                'message' => "Role synchronization completed for user '{$username}'.",
                'user_id' => $userUuid,
                'assigned_roles' => [],
                'removed_roles' => [],
                'failed_assignments' => [],
                'failed_removals' => []
            ];

            // If replace existing, get current roles and remove them
            if ($replaceExisting) {
                try {
                    $currentRoles = $this->getUserClientRolesById($userUuid);

                    foreach ($currentRoles as $currentRole) {
                        if (!in_array($currentRole['name'], $roleNames)) {
                            $removeResult = $this->removeClientRoleFromUser($username, $currentRole['name']);
                            if ($removeResult['success']) {
                                $results['removed_roles'][] = $currentRole['name'];
                            } else {
                                $results['failed_removals'][] = [
                                    'role' => $currentRole['name'],
                                    'error' => $removeResult['message']
                                ];
                            }
                        }
                    }
                } catch (\Exception $e) {
                    $results['failed_removals'][] = [
                        'error' => 'Failed to get current roles: ' . $e->getMessage()
                    ];
                }
            }

            // Assign new roles
            foreach ($roleNames as $roleName) {
                try {
                    $assignResult = $this->assignClientRoleToUser($username, $roleName);
                    if ($assignResult['success']) {
                        $results['assigned_roles'][] = $roleName;
                    } else {
                        $results['failed_assignments'][] = [
                            'role' => $roleName,
                            'error' => $assignResult['message']
                        ];
                    }
                } catch (\Exception $e) {
                    $results['failed_assignments'][] = [
                        'role' => $roleName,
                        'error' => $e->getMessage()
                    ];
                }
            }

            // Determine overall success
            $hasFailures = !empty($results['failed_assignments']) || !empty($results['failed_removals']);
            if ($hasFailures) {
                $results['success'] = false;
                $results['message'] = "Role synchronization completed with some errors for user '{$username}'.";
            }

            return $results;
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => "Failed to sync roles for user '{$username}': " . $e->getMessage(),
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Bulk assign multiple roles to user
     * 
     * @param string $username
     * @param array $roleNames
     * @return array
     */
    public function bulkAssignClientRolesToUser($username, array $roleNames): array
    {
        try {
            // Get user by username
            $user = $this->getUserByUsername($username);
            $userUuid = $user['id'];

            // Get current user roles
            $currentRoles = $this->getUserClientRolesById($userUuid);
            $currentRoleNames = array_column($currentRoles, 'name');

            // Filter out roles that user already has
            $rolesToAssign = array_diff($roleNames, $currentRoleNames);

            if (empty($rolesToAssign)) {
                return [
                    'success' => true,
                    'message' => "All specified roles are already assigned to user '{$username}'.",
                    'user_id' => $userUuid,
                    'assigned_roles' => [],
                    'skipped_roles' => $roleNames
                ];
            }

            // Prepare roles data for bulk assignment
            $rolesData = [];
            $validRoles = [];
            $invalidRoles = [];

            foreach ($rolesToAssign as $roleName) {
                try {
                    $role = $this->getClientRoleByName($roleName);
                    $rolesData[] = [
                        'id' => $role['id'],
                        'name' => $role['name'],
                        'clientRole' => true,
                        'containerId' => $this->clientUuid
                    ];
                    $validRoles[] = $roleName;
                } catch (\Exception $e) {
                    $invalidRoles[] = $roleName;
                }
            }

            $result = [
                'success' => true,
                'message' => "Bulk role assignment completed for user '{$username}'.",
                'user_id' => $userUuid,
                'assigned_roles' => [],
                'skipped_roles' => array_intersect($roleNames, $currentRoleNames),
                'invalid_roles' => $invalidRoles
            ];

            // Assign valid roles in bulk
            if (!empty($rolesData)) {
                try {
                    $response = $this->request(
                        'POST',
                        "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings/clients/{$this->clientUuid}",
                        $rolesData
                    );
                    $result['assigned_roles'] = $validRoles;
                } catch (\Exception $e) {
                    $result['success'] = false;
                    $result['message'] = "Failed to assign roles to user '{$username}': " . $e->getMessage();
                    $result['error'] = $e->getMessage();
                }
            }

            return $result;
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => "Failed to bulk assign roles to user '{$username}': " . $e->getMessage(),
                'error' => $e->getMessage()
            ];
        }
    }

    /**
     * Bulk remove multiple roles from user
     * 
     * @param string $username
     * @param array $roleNames
     * @return array
     */
    public function bulkRemoveClientRolesFromUser($username, array $roleNames): array
    {
        try {
            // Get user by username
            $user = $this->getUserByUsername($username);
            $userUuid = $user['id'];

            // Get current user roles
            $currentRoles = $this->getUserClientRolesById($userUuid);
            $currentRoleNames = array_column($currentRoles, 'name');

            // Filter roles that user actually has
            $rolesToRemove = array_intersect($roleNames, $currentRoleNames);

            if (empty($rolesToRemove)) {
                return [
                    'success' => true,
                    'message' => "None of the specified roles are assigned to user '{$username}'.",
                    'user_id' => $userUuid,
                    'removed_roles' => [],
                    'not_assigned_roles' => $roleNames
                ];
            }

            // Prepare roles data for bulk removal
            $rolesData = [];
            $validRoles = [];

            foreach ($rolesToRemove as $roleName) {
                // Find role data from current roles
                foreach ($currentRoles as $currentRole) {
                    if ($currentRole['name'] === $roleName) {
                        $rolesData[] = [
                            'id' => $currentRole['id'],
                            'name' => $currentRole['name'],
                            'clientRole' => true,
                            'containerId' => $this->clientUuid
                        ];
                        $validRoles[] = $roleName;
                        break;
                    }
                }
            }

            $result = [
                'success' => true,
                'message' => "Bulk role removal completed for user '{$username}'.",
                'user_id' => $userUuid,
                'removed_roles' => [],
                'not_assigned_roles' => array_diff($roleNames, $currentRoleNames)
            ];

            // Remove roles in bulk
            if (!empty($rolesData)) {
                try {
                    $response = $this->request(
                        'DELETE',
                        "{$this->apiUrl}admin/realms/{$this->realm}/users/{$userUuid}/role-mappings/clients/{$this->clientUuid}",
                        $rolesData
                    );
                    $result['removed_roles'] = $validRoles;
                } catch (\Exception $e) {
                    $result['success'] = false;
                    $result['message'] = "Failed to remove roles from user '{$username}': " . $e->getMessage();
                    $result['error'] = $e->getMessage();
                }
            }

            return $result;
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => "Failed to bulk remove roles from user '{$username}': " . $e->getMessage(),
                'error' => $e->getMessage()
            ];
        }
    }

    /** 
     * Set access token to the session
     */
    public function setAccessToken($token): void
    {
        Session::put('access_token', $token);
    }

    /** 
     * Set refresh token to the session
     */
    public function setRefreshToken($token): void
    {
        Session::put('refresh_token', $token);
    }
}