<?php

namespace Edoaurahman\KeycloakSso;

/**
 * Interface for Keycloak Provider Service.
 * Provides methods to interact with Keycloak API.
 */
interface KeycloakProviderServiceInterface
{
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
     * @param string|int $id The ID of the client
     * @return array New client secret information
     */
    public function regenerateClientSecret($id): array;

    /**
     * Get Roles of a user
     * 
     * @param string $id
     * @return array
     */
    public function getUserRoles($id): array;
}