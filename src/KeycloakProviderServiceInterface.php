<?php

namespace Edoaurahman\KeycloakSso;

/**
 * Interface for Keycloak Provider Service.
 * Provides methods to interact with Keycloak API.
 */
interface KeycloakProviderServiceInterface
{
    /**
     * set Base URL
     * @param string $baseUrl
     * @return void
     */
    public function setBaseUrl($baseUrl): void;
    
    /**
     * set realm
     * @param string $realm
     * @return void
     */
    public function setRealm($realm): void;

    /**
     * set token field
     * @param string $tokenField
     * @return void
     */
    public function setTokenField($tokenField): void;

    /**
     * set refresh token field
     * 
     * @param string $refreshTokenField
     * @return void
     */
    public function setRefreshTokenField($refreshTokenField): void;

    /**
     * Refresh the access token using the refresh token
     * @param string $refreshToken
     * @return void
     */
    public function refreshToken($refreshToken = null): ?string;

    /**
     * Sends a request to the Keycloak API.
     *
     * @param string $method The HTTP method to use (GET, POST, PUT, DELETE)
     * @param string $url The URL to send the request to
     * @param array $data The data to send with the request
     * @return array The response from Keycloak API
     */

    public function request($method, $url, $data = []): array;
    /**
     * Retrieves the list of clients from Keycloak.
     *
     * @return array List of clients
     */
    public function getClientList(): array;

    /**
     * Retrieves the list of users from Keycloak.
     *
     * @return array List of users
     */
    public function getUserList(): array;

    /**
     * Retrieves a specific user by ID.
     *
     * @param string|int $id The ID of the user to retrieve
     * @return array User data
     */
    public function getUser($id): array;

    /**
     * Creates a new user in Keycloak.
     *
     * @param array $data User data
     * @return array Created user information
     */
    public function createUser($data): array;

    /**
     * Updates an existing user in Keycloak.
     *
     * @param string|int $id The ID of the user to update
     * @param array $data Updated user data
     * @return array Updated user information
     */
    public function updateUser($id, $data): array;

    /**
     * Deletes a user from Keycloak.
     *
     * @param string|int $id The ID of the user to delete
     * @return array Response data
     */
    public function deleteUser($id): array;

    /**
     * Regenerates the client secret for a specified client.
     *
     * @param string|int $clientUuid The ID of the client
     * @return array New client secret information
     */
    public function regenerateClientSecret(): array;

    /**
     * Get Roles of a user
     * 
     * @param string $userUuid
     * @return array
     */
    public function getUserRoles($userUuid): array;

    /**
     * Get all roles for the client
     * 
     * @return array
     * 
     */
    public function getClientRoles(): array;

    /**
     * Get all users with a specific realm role
     * 
     * @param string $roleName
     * @return array
     * 
     */
    public function getUsersWithRole($roleName): array;

    /**
     * Get all users with their roles
     * 
     * @return array
     * 
     */
    public function getUsersWithRoles(): array;

    /**
     * Create a new role for the realm or client
     * 
     * @param array $data
     * @return array
     * 
     */
    public function createRole($data): array;

    /**
     * Get Client UUID by client ID
     * 
     * @param string $clientId
     * @return string
     * 
     */
    public function getClientUuid($clientId): string;

    /**
     * Retrieves a list of user sessions associated with the Keycloak client.
     * 
     * @return array
     * 
     */
    public function getClientSessions(): array;

    /**
     * Get client session stats Returns a JSON map.
     * 
     * @return array
     * 
     */
    public function getClientSessionStats(): array;

    /**
     * Get sessions associated with the user
     * 
     * @param string $userUuid
     * @return array
     * 
     */
    public function getUserSessionsByUserId($userUuid): array;

    /**
     * Retrieves the session details of the currently logged-in user.
     *
     * @return array
     * An array containing details of each session.
     * 
     */
    public function getCurrentUserSessions(): array;

    /**
     * Retrieves the list of clients associated with the currently logged-in user.
     * 
     * @return array
     * An array containing details of each client.
     * 
     */
    public function getCurrentUserClients(): array;
    
    /**
     * Retrieves the authentication credentials associated with the currently logged-in user.
     *
     * @return array
     * An array containing details of user credentials.
     * 
     */
    public function getCurrentUserCredentials(): array;
    
    /**
     * Retrieves the profile information of the currently logged-in user.
     * 
     * @return array
     * An array containing user profile details.
     *
     */
    public function getCurrentUserProfile(): array;
    
    /**
     * Retrieves the groups associated with the currently logged-in user.
     * 
     * @return array
     * An array containing names each group.
     * 
     */
    public function getCurrentUserGroups(): array;

    /**
     * Reset the password of a user by ID.
     * 
     * @param string $userUuid
     * @param string $newPassword
     * @return array
     * An array containing the response data.
     * 
     */
    public function resetUserPassword($userUuid, $newPassword): array;
    
    /**
     * Update the profile of the currently logged-in user.
     * 
     * @param array $data
     * @return array
     * An array containing the response data.
     * 
     */
    public function updateCurrentUserProfile($data): array;
    
    /**
     * Delete all sessions except current session associated with the currently logged-in user.
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function deleteAllCurrentUserSessions(): array;

    /**
     * Delete a session associated with the currently logged-in user by ID.
     * 
     * @param string $sessionUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function deleteCurrentUserSessionById($sessionUuid): array;

    /**
     * Send a verification email to a user to verify their email address.
     * 
     * @param string $userUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function sendVerificationEmail($userUuid): array;

    /**
     * Send a reset password email to a user to reset their password.
     * 
     * @param string $userUuid
     * @return array
     * An array containing the response data.
     * 
     */
    public function sendResetPasswordEmail($userUuid): array;

    /**
     * Check if the access token is expired
     * 
     * @return bool
     * 
     */
    public function isTokenExpired(): bool;

    /**
     * Retrieves the Keycloak client roles assigned to a specific user.
     * 
     * @param string $userUuid
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function getUserClientRoles($userUuid) : array;

    /**
     * Retrieves a list of users assigned to a specific client role.
     * 
     * @param string $roleName
     * 
     * @return array
     * An array containing the response data.
     * 
     */
    public function getUsersByClientRole($roleName) : array;

    /**
     * Get user roles by ID, in client
     * 
     * @param string $userUuid
     * @return array
     * An array containing the user roles.
     * 
     */
    public function getUserClientRolesById($userUuid): array;

    /**
     * Keycloak introspect token
     * 
     * @param string $token
     * @return array
     * An array containing the token introspection data.
     * 
     */
    public function introspectToken($token): array;

    /**
     * Get events from Keycloak
     * 
     * @return array
     * An array containing the events data.
     * 
     */
    public function getKeycloakEvents(): array;

    /**
     * Get user events from Keycloak
     * 
     * @param string $userUuid
     * @return array
     */
    public function getUserEvents($userUuid): array;
}