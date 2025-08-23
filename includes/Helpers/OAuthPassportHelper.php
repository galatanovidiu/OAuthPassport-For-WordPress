<?php
/**
 * OAuth Passport Helper Class
 *
 * Main helper class that provides a unified interface to all OAuth Passport functionality.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport\Helpers;

/**
 * Main OAuth Passport Helper class.
 *
 * This class provides a unified interface to all OAuth Passport functionality
 * and serves as the main entry point for the helper methods.
 */
class OAuthPassportHelper {

	/**
	 * Check if OAuth Passport is enabled.
	 *
	 * @return bool True if OAuth is enabled, false otherwise.
	 */
	public static function is_enabled(): bool {
		/**
		 * Filter whether OAuth Passport is enabled.
		 *
		 * @param bool $enabled Whether OAuth is enabled. Default true.
		 */
		return apply_filters( 'oauth_passport_enabled', true );
	}

	/**
	 * Get the current OAuth token if the request is authenticated via OAuth.
	 *
	 * @return object|null Token object with user_id, client_id, scope, etc. or null if not OAuth authenticated.
	 */
	public static function get_current_token() {
		return TokenManager::get_current_token();
	}

	/**
	 * Check if the current user has a specific OAuth scope.
	 *
	 * @param string $scope The scope to check for.
	 * @return bool True if the user has the scope, false otherwise.
	 */
	public static function user_has_scope( string $scope ): bool {
		return TokenManager::user_has_scope( $scope );
	}

	/**
	 * Check if the current user can perform an action (OAuth scope or WordPress capability).
	 *
	 * @param string $required_scope The OAuth scope required (e.g., 'read', 'write', 'admin').
	 * @param string $fallback_capability The WordPress capability to check if not OAuth authenticated.
	 * @return bool True if the user can perform the action, false otherwise.
	 */
	public static function user_can( string $required_scope, string $fallback_capability = '' ): bool {
		return TokenManager::user_can( $required_scope, $fallback_capability );
	}

	/**
	 * Revoke an OAuth token.
	 *
	 * @param string $token The token to revoke.
	 * @return bool True on success, false on failure.
	 */
	public static function revoke_token( string $token ): bool {
		return TokenManager::revoke_token( $token );
	}

	/**
	 * Get all available OAuth scopes.
	 *
	 * @return array Array of scope => description pairs.
	 */
	public static function get_available_scopes(): array {
		return ScopeHelper::get_available_scopes();
	}

	/**
	 * Get default OAuth scopes.
	 *
	 * @return array Array of default scope names.
	 */
	public static function get_default_scopes(): array {
		return ScopeHelper::get_default_scopes();
	}

	/**
	 * Get scope names (keys only).
	 *
	 * @return array Array of scope names.
	 */
	public static function get_scope_names(): array {
		return ScopeHelper::get_scope_names();
	}

	/**
	 * Manually register an OAuth client.
	 *
	 * @param string $client_id     The client ID.
	 * @param string $client_secret The client secret.
	 * @param string $redirect_uri  The redirect URI.
	 * @param array  $additional    Additional client data.
	 * @return bool True on success, false on failure.
	 */
	public static function register_client( string $client_id, string $client_secret, string $redirect_uri, array $additional = array() ): bool {
		return ClientManager::register_client( $client_id, $client_secret, $redirect_uri, $additional );
	}

	/**
	 * Get OAuth client by ID.
	 *
	 * @param string $client_id The client ID.
	 * @return array|null Client data or null if not found.
	 */
	public static function get_client( string $client_id ) {
		return ClientManager::get_client( $client_id );
	}

	/**
	 * Get the OAuth authorization URL.
	 *
	 * @param array $params Query parameters for the authorization request.
	 * @return string The authorization URL.
	 */
	public static function get_authorize_url( array $params = array() ): string {
		return UrlGenerator::get_authorize_url( $params );
	}

	/**
	 * Get the OAuth token URL.
	 *
	 * @return string The token endpoint URL.
	 */
	public static function get_token_url(): string {
		return UrlGenerator::get_token_url();
	}

	/**
	 * Get the OAuth client registration URL.
	 *
	 * @return string The registration endpoint URL.
	 */
	public static function get_registration_url(): string {
		return UrlGenerator::get_registration_url();
	}
}
