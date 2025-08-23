<?php
/**
 * OAuth Scope Manager
 *
 * Manages OAuth scope validation, permissions, and scope-based access control
 * for authorization requests and token generation.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use OAuthPassport\Contracts\ScopeValidatorInterface;

/**
 * Class ScopeManager
 *
 * Handles OAuth scope validation, permission checking, and scope-based
 * access control for OAuth authorization and token flows.
 */
class ScopeManager implements ScopeValidatorInterface {
	/**
	 * Available OAuth scopes with descriptions
	 *
	 * Defines the default scopes available for OAuth clients.
	 * Can be extended via the 'oauth_passport_scopes' filter.
	 *
	 * @var array<string, string>
	 */
	public const AVAILABLE_SCOPES = array(
		'read'  => 'Read your content and data',
		'write' => 'Create and edit content',
		'admin' => 'Manage site settings and users',
	);

	/**
	 * Default scopes granted to new clients
	 *
	 * These scopes are automatically granted when no specific
	 * scopes are requested during authorization.
	 *
	 * @var array<string>
	 */
	public const DEFAULT_SCOPES = array( 'read' );

	/**
	 * Get all available scopes
	 *
	 * Returns all registered OAuth scopes with their descriptions.
	 * Applies the 'oauth_passport_scopes' filter for customization.
	 *
	 * @return array<string, string> Array of scope => description pairs
	 */
	public static function get_scopes(): array {
		return apply_filters( 'oauth_passport_scopes', self::AVAILABLE_SCOPES );
	}

	/**
	 * Get default scopes (static method for global access)
	 *
	 * @return array Array of default scope names.
	 */
	public static function get_default_scopes(): array {
		return apply_filters( 'oauth_passport_default_scopes', self::DEFAULT_SCOPES );
	}

	/**
	 * Get all available scopes
	 *
	 * @return array Array of scope => description.
	 */
	public function get_available_scopes(): array {
		return self::get_scopes();
	}

	/**
	 * Get all available scopes (interface method)
	 *
	 * @return array Array of scope => description.
	 */
	public function getAvailableScopes(): array {
		return $this->get_available_scopes();
	}

	/**
	 * Validate requested scopes
	 *
	 * @param array|string $requested_scopes Space-separated string or array of scopes.
	 *
	 * @return array Valid scopes.
	 */
	public function validate_scopes( array|string $requested_scopes ): array {
		// Convert to array if string.
		if ( is_string( $requested_scopes ) ) {
			$requested_scopes = explode( ' ', $requested_scopes );
		}

		// Get available scopes.
		$available = array_keys( $this->get_available_scopes() );

		// Filter to only valid scopes.
		$valid_scopes = array_intersect( $requested_scopes, $available );

		// If no valid scopes, return defaults.
		if ( empty( $valid_scopes ) ) {
			return $this->get_default_scopes();
		}

		return array_values( $valid_scopes );
	}

	/**
	 * Validate requested scopes (interface method)
	 *
	 * @param array|string $requested_scopes Space-separated string or array of scopes.
	 *
	 * @return array Valid scopes.
	 */
	public function validateScopes( array|string $requested_scopes ): array {
		return $this->validate_scopes( $requested_scopes );
	}

	/**
	 * Check if a token has a specific scope
	 *
	 * @param string $token_scope Space-separated list of token scopes.
	 * @param string $required_scope Required scope.
	 * @return bool True if token has the required scope.
	 */
	public function has_scope( string $token_scope, string $required_scope ): bool {
		$token_scopes = explode( ' ', $token_scope );
		return in_array( $required_scope, $token_scopes, true );
	}

	/**
	 * Check if a token has a specific scope (interface method)
	 *
	 * @param string $token_scope Space-separated list of token scopes.
	 * @param string $required_scope Required scope.
	 * @return bool True if token has the required scope.
	 */
	public function hasScope( string $token_scope, string $required_scope ): bool {
		return $this->has_scope( $token_scope, $required_scope );
	}

	/**
	 * Check if a token has all required scopes
	 *
	 * @param string $token_scope Space-separated list of token scopes.
	 * @param array  $required_scopes Array of required scopes.
	 * @return bool True if token has all required scopes.
	 */
	public function has_all_scopes( string $token_scope, array $required_scopes ): bool {
		$token_scopes = explode( ' ', $token_scope );
		return count( array_intersect( $required_scopes, $token_scopes ) ) === count( $required_scopes );
	}

	/**
	 * Check if a token has all required scopes (interface method)
	 *
	 * @param string $token_scope Space-separated list of token scopes.
	 * @param array  $required_scopes Array of required scopes.
	 * @return bool True if token has all required scopes.
	 */
	public function hasAllScopes( string $token_scope, array $required_scopes ): bool {
		return $this->has_all_scopes( $token_scope, $required_scopes );
	}

	/**
	 * Check if a token has any of the required scopes
	 *
	 * @param string $token_scope Space-separated list of token scopes.
	 * @param array  $required_scopes Array of required scopes.
	 * @return bool True if token has any of the required scopes.
	 */
	public function has_any_scope( string $token_scope, array $required_scopes ): bool {
		$token_scopes = explode( ' ', $token_scope );
		return count( array_intersect( $required_scopes, $token_scopes ) ) > 0;
	}

	/**
	 * Format scopes for display
	 *
	 * @param array|string $scopes Space-separated string or array of scopes.
	 *
	 * @return string Human-readable scope descriptions.
	 */
	public function format_scopes_for_display( array|string $scopes ): string {
		if ( is_string( $scopes ) ) {
			$scopes = explode( ' ', $scopes );
		}

		$available     = $this->get_available_scopes();
		$descriptions  = array();

		foreach ( $scopes as $scope ) {
			if ( isset( $available[ $scope ] ) ) {
				$descriptions[] = $available[ $scope ];
			}
		}

		return implode( ', ', $descriptions );
	}

	/**
	 * Get scopes as string
	 *
	 * @param array $scopes Array of scopes.
	 * @return string Space-separated string of scopes.
	 */
	public function scopes_to_string( array $scopes ): string {
		return implode( ' ', $scopes );
	}

	/**
	 * Validate scope for REST request
	 *
	 * @param string $required_scope Required scope for the endpoint.
	 * @param string $token_scope Token's granted scopes.
	 * @return bool|\WP_Error True, if valid, WP_Error otherwise.
	 */
	public function validate_request_scope( string $required_scope, string $token_scope ) :bool|\WP_Error {
		if ( ! $this->has_scope( $token_scope, $required_scope ) ) {
			return new \WP_Error(
				'insufficient_scope',
				'The access token does not have the required scope: ' . $required_scope,
				array(
					'status'         => 403,
					'required_scope' => $required_scope,
					'token_scope'    => $token_scope,
				)
			);
		}

		return true;
	}

	/**
	 * Get WordPress capabilities for OAuth scopes
	 *
	 * Maps OAuth scopes to WordPress capabilities.
	 *
	 * @param string $scope OAuth scope.
	 * @return array WordPress capabilities.
	 */
	public function get_capabilities_for_scope( string $scope ): array {
		$scope_capabilities = array(
			'read'  => array( 'read' ),
			'write' => array( 'edit_posts', 'publish_posts', 'edit_pages', 'publish_pages', 'upload_files' ),
			'admin' => array( 'manage_options', 'list_users', 'edit_users', 'delete_users', 'manage_categories' ),
		);

		$scope_capabilities = apply_filters( 'oauth_passport_scope_capabilities', $scope_capabilities );

		return $scope_capabilities[ $scope ] ?? array();
	}

	/**
	 * Check if user has capabilities for scope
	 *
	 * @param int    $user_id User ID.
	 * @param string $scope OAuth scope.
	 * @return bool True if user has all required capabilities.
	 */
	public function user_can_access_scope( int $user_id, string $scope ): bool {
		$capabilities = $this->get_capabilities_for_scope( $scope );

		if ( empty( $capabilities ) ) {
			return true; // No specific capabilities required.
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		foreach ( $capabilities as $capability ) {
			if ( ! user_can( $user, $capability ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check if user has capabilities for scope (interface method)
	 *
	 * @param int    $user_id User ID.
	 * @param string $scope OAuth scope.
	 * @return bool True if user has all required capabilities.
	 */
	public function userCanAccessScope( int $user_id, string $scope ): bool {
		return $this->user_can_access_scope( $user_id, $scope );
	}

	/**
	 * Filter scopes based on user capabilities
	 *
	 * @param array $scopes Requested scopes.
	 * @param int   $user_id User ID.
	 * @return array Scopes the user can actually access.
	 */
	public function filter_scopes_by_user_capabilities( array $scopes, int $user_id ): array {
		$filtered = array();

		foreach ( $scopes as $scope ) {
			if ( $this->user_can_access_scope( $user_id, $scope ) ) {
				$filtered[] = $scope;
			}
		}

		// Always include at least read scope if user is logged in.
		if ( empty( $filtered ) && $user_id > 0 ) {
			$filtered[] = 'read';
		}

		return $filtered;
	}

	/**
	 * Filter scopes based on user capabilities (interface method)
	 *
	 * @param array $scopes Requested scopes.
	 * @param int   $user_id User ID.
	 * @return array Scopes the user can actually access.
	 */
	public function filterScopesByUserCapabilities( array $scopes, int $user_id ): array {
		return $this->filter_scopes_by_user_capabilities( $scopes, $user_id );
	}
}
