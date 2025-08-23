<?php
/**
 * Scope Helper Class
 *
 * Handles OAuth scope operations.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport\Helpers;

use OAuthPassport\Auth\ScopeManager;

/**
 * Scope Helper class for handling OAuth scope operations.
 */
class ScopeHelper {

	/**
	 * Get all available OAuth scopes.
	 *
	 * @return array Array of scope => description pairs.
	 */
	public static function get_available_scopes(): array {
		return ScopeManager::get_scopes();
	}

	/**
	 * Get default OAuth scopes.
	 *
	 * @return array Array of default scope names.
	 */
	public static function get_default_scopes(): array {
		return ScopeManager::get_default_scopes();
	}

	/**
	 * Get scope names (keys only).
	 *
	 * @return array Array of scope names.
	 */
	public static function get_scope_names(): array {
		return array_keys( ScopeManager::get_scopes() );
	}
}
