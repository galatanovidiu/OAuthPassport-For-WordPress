<?php
/**
 * Token Manager Class
 *
 * Handles OAuth token operations.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport\Helpers;

use OAuthPassport\Auth\ScopeManager;

/**
 * Token Manager class for handling OAuth token operations.
 */
class TokenManager {

	/**
	 * Get the current OAuth token if the request is authenticated via OAuth.
	 *
	 * @return object|null Token object with user_id, client_id, scope, etc. or null if not OAuth authenticated.
	 */
	public static function get_current_token() {
		// Check if we have an OAuth token in the current request.
		$auth_header = '';
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			$auth_header = sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) );
		}

		if ( empty( $auth_header ) || ! preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			return null;
		}

		$token = $matches[1];

		// Skip if it looks like a JWT (has dots).
		if ( str_contains( $token, '.' ) ) {
			return null;
		}

		// Look up the token in the database.
		global $wpdb;
		$table = $wpdb->prefix . 'oauth_passport_tokens';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$token_data = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i 
				WHERE token_type = 'access' 
				AND token_value = %s 
				AND expires_at > %s",
				$table,
				$token,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		return $token_data;
	}

	/**
	 * Check if the current user has a specific OAuth scope.
	 *
	 * @param string $scope The scope to check for.
	 * @return bool True if the user has the scope, false otherwise.
	 */
	public static function user_has_scope( string $scope ): bool {
		$token = self::get_current_token();
		if ( ! $token ) {
			return false;
		}

		$token_scopes = explode( ' ', $token->scope );
		return in_array( $scope, $token_scopes, true );
	}

	/**
	 * Check if the current user can perform an action (OAuth scope or WordPress capability).
	 *
	 * This function provides a unified way to check permissions for both OAuth and regular WordPress requests.
	 * For OAuth requests, it checks if the user has the required scope.
	 * For regular requests, it checks WordPress capabilities.
	 *
	 * @param string $required_scope The OAuth scope required (e.g., 'read', 'write', 'admin').
	 * @param string $fallback_capability The WordPress capability to check if not OAuth authenticated.
	 * @return bool True if the user can perform the action, false otherwise.
	 */
	public static function user_can( string $required_scope, string $fallback_capability = '' ): bool {
		$token = self::get_current_token();
		
		if ( $token ) {
			// OAuth request - check scope
			return self::user_has_scope( $required_scope );
		}
		
		// Regular WordPress request - check capability
		if ( empty( $fallback_capability ) ) {
			// Use the centralized scope manager to get capabilities
			$scope_manager = new ScopeManager();
			$capabilities = $scope_manager->get_capabilities_for_scope( $required_scope );
			$fallback_capability = ! empty( $capabilities ) ? $capabilities[0] : 'read';
		}
		
		return current_user_can( $fallback_capability );
	}

	/**
	 * Revoke an OAuth token.
	 *
	 * @param string $token The token to revoke.
	 * @return bool True on success, false on failure.
	 */
	public static function revoke_token( string $token ): bool {
		global $wpdb;
		$table = $wpdb->prefix . 'oauth_passport_tokens';

		$result = $wpdb->delete(
			$table,
			array( 'token_value' => $token )
		);

		return false !== $result;
	}
}
