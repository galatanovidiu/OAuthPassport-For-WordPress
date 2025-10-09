<?php
/**
 * Token Repository Implementation
 *
 * Manages OAuth token storage and retrieval using WordPress database
 * with timing-safe validation and automatic cleanup of expired tokens.
 *
 * @package OAuthPassport
 * @subpackage Repositories
 */

declare( strict_types=1 );

namespace OAuthPassport\Repositories;

use OAuthPassport\Auth\SecurityUtils;

/**
 * Class TokenRepository
 *
 * WordPress database implementation for OAuth token storage and retrieval
 * with secure validation and expiration management.
 */
class TokenRepository {

	/**
	 * OAuth tokens database table name
	 *
	 * @var string
	 */
	private string $table_name;

	/**
	 * Initialize token repository
	 *
	 * Sets up the database table name for OAuth token storage.
	 */
	public function __construct() {
		global $wpdb;
		$this->table_name = $wpdb->prefix . 'oauth_passport_tokens';
	}

	/**
	 * Store access token
	 *
	 * Stores an OAuth access token in the database with expiration time
	 * and associated client and user information.
	 *
	 * @param string $token Access token value
	 * @param string $client_id Associated client ID
	 * @param int    $user_id Associated user ID
	 * @param string $scope Token scope permissions
	 * @param int    $expires_in Expiration time in seconds from now
	 * @return bool True on success
	 */
	public function storeAccessToken( string $token, string $client_id, int $user_id, string $scope = 'read write', int $expires_in = 3600 ): bool {
		global $wpdb;

		$result = $wpdb->insert(
			$this->table_name,
			array(
				'token_type'  => 'access',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + $expires_in ),
				'token_version' => '2.0',
			)
		);

		return false !== $result;
	}

	/**
	 * Store refresh token
	 *
	 * Stores an OAuth refresh token in the database with longer expiration
	 * time for token renewal operations.
	 *
	 * @param string $token Refresh token value
	 * @param string $client_id Associated client ID
	 * @param int    $user_id Associated user ID
	 * @param string $scope Token scope permissions
	 * @param int    $expires_in Expiration time in seconds from now
	 * @return bool True on success
	 */
	public function storeRefreshToken( string $token, string $client_id, int $user_id, string $scope = 'read write', int $expires_in = 2592000 ): bool {
		global $wpdb;

		$result = $wpdb->insert(
			$this->table_name,
			array(
				'token_type'  => 'refresh',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + $expires_in ),
				'token_version' => '2.0',
			)
		);

		return false !== $result;
	}

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
	public function storeAuthCode( string $code, string $client_id, int $user_id, string $code_challenge, string $scope = 'read write', int $expires_in = 300 ): bool {
		global $wpdb;

		$result = $wpdb->insert(
			$this->table_name,
			array(
				'token_type'     => 'code',
				'token_value'    => $code,
				'client_id'      => $client_id,
				'user_id'        => $user_id,
				'code_challenge' => $code_challenge,
				'scope'          => $scope,
				'expires_at'     => gmdate( 'Y-m-d H:i:s', time() + $expires_in ),
				'token_version'  => '2.0',
			)
		);

		return false !== $result;
	}

	/**
	 * Validate access token
	 *
	 * @param string $token Access token
	 * @return object|null Token data or null if invalid
	 */
	public function validateAccessToken( string $token ): ?object {
		global $wpdb;

		// Get all active access tokens to prevent timing attacks
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_id, client_id, token_value, scope FROM %i 
				WHERE token_type = 'access' 
				AND expires_at > %s",
				$this->table_name,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		// Use timing-safe comparison to find matching token
		foreach ( $tokens as $stored_token ) {
			if ( SecurityUtils::validateToken( $token, $stored_token->token_value ) ) {
				return $stored_token;
			}
		}

		return null;
	}

	/**
	 * Get authorization code
	 *
	 * @param string $code Authorization code
	 * @return object|null Code data or null if not found
	 */
	public function getAuthCode( string $code ): ?object {
		global $wpdb;

		$table = esc_sql( $this->table_name );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} 
				WHERE token_type = 'code' 
				AND token_value = %s 
				AND expires_at > %s",
				$code,
				current_time( 'mysql' )
			)
		);
	}

	/**
	 * Get refresh token
	 *
	 * @param string $token Refresh token
	 * @return object|null Token data or null if not found
	 */
	public function getRefreshToken( string $token ): ?object {
		global $wpdb;

		$table = esc_sql( $this->table_name );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$table} 
				WHERE token_type = 'refresh' 
				AND token_value = %s 
				AND expires_at > %s",
				$token,
				current_time( 'mysql' )
			)
		);
	}

	/**
	 * Delete token by value
	 *
	 * @param string $token Token value
	 * @return bool True on success
	 */
	public function deleteToken( string $token ): bool {
		global $wpdb;

		$result = $wpdb->delete(
			$this->table_name,
			array( 'token_value' => $token )
		);

		return false !== $result;
	}

	/**
	 * Delete token by ID
	 *
	 * @param int $token_id Token ID
	 * @return bool True on success
	 */
	public function deleteTokenById( int $token_id ): bool {
		global $wpdb;

		$result = $wpdb->delete(
			$this->table_name,
			array( 'id' => $token_id )
		);

		return false !== $result;
	}

	/**
	 * Clean up expired tokens
	 *
	 * @return int Number of deleted tokens
	 */
	public function cleanupExpiredTokens(): int {
		global $wpdb;

		$table = esc_sql( $this->table_name );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$deleted = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE expires_at < %s",
				current_time( 'mysql' )
			)
		);

		return $deleted ? $deleted : 0;
	}

	/**
	 * Store authorization code (alias for storeAuthCode)
	 *
	 * @param string $code Authorization code
	 * @param string $client_id Client ID
	 * @param int    $user_id User ID
	 * @param string $code_challenge PKCE challenge
	 * @param string $scope Requested scope
	 * @param int    $expires_in Expiration time in seconds
	 * @return bool True on success
	 */
	public function storeAuthorizationCode( string $code, string $client_id, int $user_id, string $code_challenge, string $scope = 'read write', int $expires_in = 300 ): bool {
		return $this->storeAuthCode( $code, $client_id, $user_id, $code_challenge, $scope, $expires_in );
	}

	/**
	 * Get access token
	 *
	 * @param string $token Access token
	 * @return array|null Token data or null if invalid
	 */
	public function getAccessToken( string $token ): ?array {
		$token_data = $this->validateAccessToken( $token );
		return $token_data ? (array) $token_data : null;
	}

	/**
	 * Get authorization code (alias for getAuthCode)
	 *
	 * @param string $code Authorization code
	 * @return array|null Code data or null if not found
	 */
	public function getAuthorizationCode( string $code ): ?array {
		$code_data = $this->getAuthCode( $code );
		return $code_data ? (array) $code_data : null;
	}

	/**
	 * Revoke access token
	 *
	 * @param string $token Access token
	 * @return bool True on success
	 */
	public function revokeAccessToken( string $token ): bool {
		return $this->deleteToken( $token );
	}

	/**
	 * Revoke refresh token
	 *
	 * @param string $token Refresh token
	 * @return bool True on success
	 */
	public function revokeRefreshToken( string $token ): bool {
		return $this->deleteToken( $token );
	}

	/**
	 * Consume authorization code (delete after use)
	 *
	 * @param string $code Authorization code
	 * @return bool True on success
	 */
	public function consumeAuthorizationCode( string $code ): bool {
		return $this->deleteToken( $code );
	}

	/**
	 * Get token statistics
	 *
	 * @return array Token statistics
	 */
	public function getTokenStatistics(): array {
		global $wpdb;

		$table = esc_sql( $this->table_name );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$stats = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT token_type, COUNT(*) as count FROM {$table} WHERE expires_at > %s GROUP BY token_type",
				current_time( 'mysql' )
			),
			ARRAY_A
		);

		$result = array(
			'access' => 0,
			'refresh' => 0,
			'code' => 0,
		);

		foreach ( $stats as $stat ) {
			$result[ $stat['token_type'] ] = (int) $stat['count'];
		}

		return $result;
	}

	/**
	 * Revoke all user tokens
	 *
	 * @param int $user_id User ID
	 * @return bool True on success
	 */
	public function revokeAllUserTokens( int $user_id ): bool {
		global $wpdb;

		$result = $wpdb->delete(
			$this->table_name,
			array( 'user_id' => $user_id )
		);

		return false !== $result;
	}

	/**
	 * Revoke all client tokens
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function revokeAllClientTokens( string $client_id ): bool {
		global $wpdb;

		$result = $wpdb->delete(
			$this->table_name,
			array( 'client_id' => $client_id )
		);

		return false !== $result;
	}

	/**
	 * Get user tokens
	 *
	 * @param int $user_id User ID
	 * @return array Array of user tokens
	 */
	public function getUserTokens( int $user_id ): array {
		global $wpdb;

		$table = esc_sql( $this->table_name );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE user_id = %d AND expires_at > %s",
				$user_id,
				current_time( 'mysql' )
			),
			ARRAY_A
		);

		return $tokens ?: array();
	}

	/**
	 * Get client tokens
	 *
	 * @param string $client_id Client ID
	 * @return array Array of client tokens
	 */
	public function getClientTokens( string $client_id ): array {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$table = esc_sql( $this->table_name );
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE client_id = %s AND expires_at > %s",
				$client_id,
				current_time( 'mysql' )
			),
			ARRAY_A
		);

		return $tokens ?: array();
	}

}
