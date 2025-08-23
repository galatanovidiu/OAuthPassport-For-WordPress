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

use OAuthPassport\Contracts\TokenRepositoryInterface;
use OAuthPassport\Auth\SecurityUtils;

/**
 * Class TokenRepository
 *
 * WordPress database implementation for OAuth token storage and retrieval
 * with secure validation and expiration management.
 */
class TokenRepository implements TokenRepositoryInterface {

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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i 
				WHERE token_type = 'code' 
				AND token_value = %s 
				AND expires_at > %s",
				$this->table_name,
				$code,
				gmdate( 'Y-m-d H:i:s' )
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i 
				WHERE token_type = 'refresh' 
				AND token_value = %s 
				AND expires_at > %s",
				$this->table_name,
				$token,
				gmdate( 'Y-m-d H:i:s' )
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$deleted = $wpdb->query(
			$wpdb->prepare(
				'DELETE FROM %i WHERE expires_at < %s',
				$this->table_name,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		return $deleted ? $deleted : 0;
	}
}
