<?php
/**
 * Scope Validator Interface
 *
 * Defines the contract for OAuth scope validation, permission checking,
 * and user capability-based access control.
 *
 * @package OAuthPassport
 * @subpackage Contracts
 */

declare( strict_types=1 );

namespace OAuthPassport\Contracts;

/**
 * Interface ScopeValidatorInterface
 *
 * Contract for OAuth scope validation, permission checking,
 * and user capability-based access control.
 */
interface ScopeValidatorInterface {

	/**
	 * Get all available scopes
	 *
	 * Returns all registered OAuth scopes with their human-readable descriptions.
	 *
	 * @return array<string, string> Array of scope => description pairs
	 */
	public function getAvailableScopes(): array;

	/**
	 * Validate requested scopes
	 *
	 * Filters requested scopes to only include valid, registered scopes.
	 * Returns default scopes if no valid scopes are provided.
	 *
	 * @param array|string $requested_scopes Space-separated string or array of scopes
	 *
	 * @return array<string> Valid scopes
	 */
	public function validateScopes( array|string $requested_scopes ): array;

	/**
	 * Check if a token has a specific scope
	 *
	 * @param string $token_scope Space-separated list of token scopes
	 * @param string $required_scope Required scope
	 * @return bool True if token has the required scope
	 */
	public function hasScope( string $token_scope, string $required_scope ): bool;

	/**
	 * Check if a token has all required scopes
	 *
	 * @param string $token_scope Space-separated list of token scopes
	 * @param array  $required_scopes Array of required scopes
	 * @return bool True if token has all required scopes
	 */
	public function hasAllScopes( string $token_scope, array $required_scopes ): bool;

	/**
	 * Check if user has capabilities for scope
	 *
	 * Verifies that a user has the WordPress capabilities required
	 * to access the specified OAuth scope.
	 *
	 * @param int    $user_id User ID
	 * @param string $scope OAuth scope
	 * @return bool True if user has all required capabilities
	 */
	public function userCanAccessScope( int $user_id, string $scope ): bool;

	/**
	 * Filter scopes based on user capabilities
	 *
	 * Filters requested scopes to only include those the user
	 * has sufficient WordPress capabilities to access.
	 *
	 * @param array<string> $scopes Requested scopes
	 * @param int   $user_id User ID
	 * @return array<string> Scopes the user can actually access
	 */
	public function filterScopesByUserCapabilities( array $scopes, int $user_id ): array;
}
