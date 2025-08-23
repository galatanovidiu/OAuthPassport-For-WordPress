<?php
/**
 * Token Repository Interface
 *
 * Defines the contract for token storage and retrieval operations.
 *
 * @package OAuthPassport
 * @subpackage Contracts
 */

declare( strict_types=1 );

namespace OAuthPassport\Contracts;

/**
 * Interface TokenRepositoryInterface
 *
 * Contract for token storage and retrieval operations.
 */
interface TokenRepositoryInterface {

	/**
	 * Store access token
	 *
	 * @param string $token Access token
	 * @param string $client_id Client ID
	 * @param int    $user_id User ID
	 * @param string $scope Token scope
	 * @param int    $expires_in Expiration time in seconds
	 * @return bool True on success
	 */
	public function storeAccessToken( string $token, string $client_id, int $user_id, string $scope = 'read write', int $expires_in = 3600 ): bool;

	/**
	 * Store refresh token
	 *
	 * @param string $token Refresh token
	 * @param string $client_id Client ID
	 * @param int    $user_id User ID
	 * @param string $scope Token scope
	 * @param int    $expires_in Expiration time in seconds
	 * @return bool True on success
	 */
	public function storeRefreshToken( string $token, string $client_id, int $user_id, string $scope = 'read write', int $expires_in = 2592000 ): bool;

	/**
	 * Store authorization code
	 *
	 * @param string $code Authorization code
	 * @param string $client_id Client ID
	 * @param int    $user_id User ID
	 * @param string $code_challenge PKCE challenge
	 * @param string $scope Requested scope
	 * @param int    $expires_in Expiration time in seconds
	 * @return bool True on success
	 */
	public function storeAuthCode( string $code, string $client_id, int $user_id, string $code_challenge, string $scope = 'read write', int $expires_in = 300 ): bool;

	/**
	 * Validate access token
	 *
	 * @param string $token Access token
	 * @return object|null Token data or null if invalid
	 */
	public function validateAccessToken( string $token ): ?object;

	/**
	 * Get authorization code
	 *
	 * @param string $code Authorization code
	 * @return object|null Code data or null if not found
	 */
	public function getAuthCode( string $code ): ?object;

	/**
	 * Get refresh token
	 *
	 * @param string $token Refresh token
	 * @return object|null Token data or null if not found
	 */
	public function getRefreshToken( string $token ): ?object;

	/**
	 * Delete token by value
	 *
	 * @param string $token Token value
	 * @return bool True on success
	 */
	public function deleteToken( string $token ): bool;

	/**
	 * Delete token by ID
	 *
	 * @param int $token_id Token ID
	 * @return bool True on success
	 */
	public function deleteTokenById( int $token_id ): bool;

	/**
	 * Clean up expired tokens
	 *
	 * @return int Number of deleted tokens
	 */
	public function cleanupExpiredTokens(): int;
}
