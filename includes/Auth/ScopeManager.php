<?php
/**
 * OAuth Scope Manager for OAuth Passport
 *
 * Manages OAuth scopes and permissions.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class ScopeManager
 *
 * Manages OAuth scopes for OAuth Passport.
 */
class ScopeManager {
	/**
	 * Available OAuth scopes
	 *
	 * @var array
	 */
	private const AVAILABLE_SCOPES = array(
		'read'       => 'Read access to protected resources',
		'write'      => 'Write access to protected resources',
		'admin'      => 'Administrative access',
		'user:read'  => 'Read user information',
		'user:write' => 'Modify user information',
	);

	/**
	 * Default scopes for new clients
	 *
	 * @var array
	 */
	private const DEFAULT_SCOPES = array( 'read', 'write' );

	/**
	 * Get all available scopes
	 *
	 * @return array Array of scope => description.
	 */
	public function get_available_scopes(): array {
		return apply_filters( 'oauth_passport_available_scopes', self::AVAILABLE_SCOPES );
	}

	/**
	 * Get default scopes
	 *
	 * @return array Array of default scope names.
	 */
	public function get_default_scopes(): array {
		return apply_filters( 'oauth_passport_default_scopes', self::DEFAULT_SCOPES );
	}

	/**
	 * Validate requested scopes
	 *
	 * @param string|array $requested_scopes Space-separated string or array of scopes.
	 * @return array Valid scopes.
	 */
	public function validate_scopes( $requested_scopes ): array {
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
	 * @param string|array $scopes Space-separated string or array of scopes.
	 * @return string Human-readable scope descriptions.
	 */
	public function format_scopes_for_display( $scopes ): string {
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
	 * @return bool|\WP_Error True if valid, WP_Error otherwise.
	 */
	public function validate_request_scope( string $required_scope, string $token_scope ) {
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
			'read'       => array( 'read' ),
			'write'      => array( 'edit_posts', 'publish_posts' ),
			'admin'      => array( 'manage_options' ),
			'user:read'  => array( 'list_users' ),
			'user:write' => array( 'edit_users' ),
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
}
