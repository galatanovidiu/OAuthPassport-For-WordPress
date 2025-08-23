<?php
/**
 * Authentication Context
 *
 * Manages OAuth authentication state and operations for the current request context.
 * Provides token validation, scope checking, and user authentication status.
 *
 * @package OAuthPassport
 * @subpackage Context
 */

declare( strict_types=1 );

namespace OAuthPassport\Context;

use OAuthPassport\Contracts\TokenRepositoryInterface;
use OAuthPassport\Contracts\ScopeValidatorInterface;
use OAuthPassport\Services\TokenService;

/**
 * Class AuthenticationContext
 *
 * Provides OAuth authentication context including token validation,
 * scope verification, and user authentication status for the current request.
 */
class AuthenticationContext {

	/**
	 * Token service
	 *
	 * @var TokenService
	 */
	private TokenService $token_service;

	/**
	 * Scope validator
	 *
	 * @var ScopeValidatorInterface
	 */
	private ScopeValidatorInterface $scope_validator;

	/**
	 * Current OAuth token (cached)
	 *
	 * Cached token data to avoid multiple database lookups.
	 * False indicates not yet loaded, null indicates no token.
	 *
	 * @var object|null|false
	 */
	private null|false|object $current_token = false;

	/**
	 * Initialize authentication context
	 *
	 * @param TokenService            $token_service Service for token operations
	 * @param ScopeValidatorInterface $scope_validator Service for scope validation
	 */
	public function __construct( TokenService $token_service, ScopeValidatorInterface $scope_validator ) {
		$this->token_service = $token_service;
		$this->scope_validator = $scope_validator;
	}

	/**
	 * Get current OAuth token
	 *
	 * Retrieves and caches the OAuth token from the current request.
	 * Returns null if no valid OAuth token is present.
	 *
	 * @return object|null Token data or null if not authenticated via OAuth
	 */
	public function getCurrentToken(): ?object {
		if ( false === $this->current_token ) {
			$this->current_token = $this->extractTokenFromRequest();
		}
		
		return $this->current_token ?: null;
	}

	/**
	 * Check if current request is OAuth authenticated
	 *
	 * Determines whether the current request contains a valid OAuth access token.
	 *
	 * @return bool True if authenticated via OAuth
	 */
	public function isOAuthAuthenticated(): bool {
		return null !== $this->getCurrentToken();
	}

	/**
	 * Check if current user has specific OAuth scope
	 *
	 * @param string $scope Required scope
	 * @return bool True if user has scope
	 */
	public function hasScope( string $scope ): bool {
		$token = $this->getCurrentToken();
		if ( ! $token ) {
			return false;
		}

		return $this->scope_validator->hasScope( $token->scope ?? '', $scope );
	}

	/**
	 * Check if current user has all required scopes
	 *
	 * @param array $scopes Required scopes
	 * @return bool True if user has all scopes
	 */
	public function hasAllScopes( array $scopes ): bool {
		$token = $this->getCurrentToken();
		if ( ! $token ) {
			return false;
		}

		return $this->scope_validator->hasAllScopes( $token->scope ?? '', $scopes );
	}

	/**
	 * Get current user ID from OAuth token or WordPress session
	 *
	 * @return int User ID or 0 if not authenticated
	 */
	public function getCurrentUserId(): int {
		$token = $this->getCurrentToken();
		if ( $token ) {
			return (int) $token->user_id;
		}

		return get_current_user_id();
	}

	/**
	 * Get current client ID (OAuth only)
	 *
	 * @return string|null Client ID or null if not OAuth authenticated
	 */
	public function getCurrentClientId(): ?string {
		$token = $this->getCurrentToken();
		return $token ? $token->client_id : null;
	}

	/**
	 * Check if user can perform action (OAuth scope or WordPress capability)
	 *
	 * @param string $required_scope OAuth scope required
	 * @param string $fallback_capability WordPress capability for non-OAuth requests
	 * @return bool True if user can perform action
	 */
	public function userCan( string $required_scope, string $fallback_capability = '' ): bool {
		if ( $this->isOAuthAuthenticated() ) {
			return $this->hasScope( $required_scope );
		}

		// Fallback to WordPress capabilities
		if ( empty( $fallback_capability ) ) {
			$capability_map = array(
				'read'  => 'read',
				'write' => 'edit_posts',
				'admin' => 'manage_options',
			);
			$fallback_capability = $capability_map[ $required_scope ] ?? 'read';
		}

		return current_user_can( $fallback_capability );
	}

	/**
	 * Get authentication method
	 *
	 * @return string 'oauth', 'wordpress', or 'none'
	 */
	public function getAuthenticationMethod(): string {
		if ( $this->isOAuthAuthenticated() ) {
			return 'oauth';
		}

		if ( is_user_logged_in() ) {
			return 'wordpress';
		}

		return 'none';
	}

	/**
	 * Extract token from current request
	 *
	 * @return object|null Token data or null
	 */
	private function extractTokenFromRequest(): ?object {
		// Check for Bearer token in Authorization header
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

		// Skip if it looks like a JWT (has dots)
		if ( str_contains( $token, '.' ) ) {
			return null;
		}

		return $this->token_service->validateAccessToken( $token );
	}
}
