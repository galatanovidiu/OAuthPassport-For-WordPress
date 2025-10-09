<?php
/**
 * OAuth Scope Manager
 *
 * Minimal scope management helper. Provides validation, capability checks,
 * and small presentation helpers for the built-in scopes.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

class ScopeManager {
	private const DEFAULT_SCOPES = array( 'read' );

	private const AVAILABLE_SCOPES = array(
		'read'  => 'Read your content and data',
		'write' => 'Create and edit content',
		'admin' => 'Manage site settings and users',
	);

	/**
	 * Return all known scopes keyed by slug.
	 *
	 * @return array<string, string>
	 */
	public function getAvailableScopes(): array {
		$scopes = apply_filters( 'oauth_passport_scopes', self::AVAILABLE_SCOPES );

		return is_array( $scopes ) ? $scopes : self::AVAILABLE_SCOPES;
	}

	/**
	 * Return default scopes.
	 *
	 * @return array<int, string>
	 */
	public function getDefaultScopes(): array {
		$defaults = apply_filters( 'oauth_passport_default_scopes', self::DEFAULT_SCOPES );

		return is_array( $defaults ) ? array_values( $defaults ) : self::DEFAULT_SCOPES;
	}

	/**
	 * Validate a requested scope list against registered scopes.
	 *
	 * @param array<int, string>|string $requested Raw request value.
	 *
	 * @return array<int, string>
	 */
	public function validate( array|string $requested ): array {
		$requested_scopes = $this->normalise( $requested );
		$available_keys   = array_keys( $this->getAvailableScopes() );

		$valid = array_values( array_intersect( $requested_scopes, $available_keys ) );

		return empty( $valid ) ? $this->getDefaultScopes() : $valid;
	}

	/**
	 * Filter a list of scopes so it only contains the ones a user can access.
	 *
	 * @param array<int, string>|string $scopes  Scope list.
	 * @param int                       $user_id WordPress user ID.
	 *
	 * @return array<int, string>
	 */
	public function filterForUser( array|string $scopes, int $user_id ): array {
		$scopes   = $this->validate( $scopes );
		$filtered = array();

		foreach ( $scopes as $scope ) {
			if ( $this->userCanAccessScope( $user_id, $scope ) ) {
				$filtered[] = $scope;
			}
		}

		if ( empty( $filtered ) && $user_id > 0 ) {
			$filtered[] = 'read';
		}

		return $filtered;
	}

	/**
	 * Determine whether a user has the capabilities required for a scope.
	 */
	public function userCanAccessScope( int $user_id, string $scope ): bool {
		$required = $this->capabilitiesForScope( $scope );
		if ( empty( $required ) ) {
			return true;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user ) {
			return false;
		}

		foreach ( $required as $capability ) {
			if ( ! user_can( $user, $capability ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Provide human friendly descriptions for a scope list.
	 *
	 * @param array<int, string>|string $scopes Scope list.
	 */
	public function describe( array|string $scopes ): string {
		$available     = $this->getAvailableScopes();
		$target_scopes = $this->normalise( $scopes );

		$parts = array();
		foreach ( $target_scopes as $scope ) {
			$parts[] = $available[ $scope ] ?? $scope;
		}

		return implode( ', ', $parts );
	}

	/**
	 * Normalise a scope input to a tidy array of slugs.
	 *
	 * @param array<int, string>|string $scopes Scope input.
	 *
	 * @return array<int, string>
	 */
	private function normalise( array|string $scopes ): array {
		if ( is_string( $scopes ) ) {
			$scopes = preg_split( '/\s+/', trim( $scopes ) ) ?: array();
		}

		$scopes = array_filter( array_map( 'trim', $scopes ) );

		return array_values( $scopes );
	}

	/**
	 * Capability requirements per scope.
	 *
	 * @return array<string, array<int, string>>
	 */
	private function capabilitiesForScope( string $scope ): array {
		$map = apply_filters(
			'oauth_passport_scope_capabilities',
			array(
				'read'  => array( 'read' ),
				'write' => array( 'edit_posts', 'upload_files' ),
				'admin' => array( 'manage_options' ),
			)
		);

		return $map[ $scope ] ?? array();
	}
}
