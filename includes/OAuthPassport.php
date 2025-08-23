<?php
/**
 * OAuth Passport Main API
 *
 * Primary facade for OAuth Passport functionality providing access to all
 * OAuth operations through context-specific interfaces.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport;

use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Container\ServiceContainer;
use OAuthPassport\Context\AuthenticationContext;
use OAuthPassport\Context\ClientContext;
use OAuthPassport\Context\UrlContext;
use OAuthPassport\Services\TokenService;

/**
 * Class OAuthPassport
 *
 * Main API facade providing organized access to OAuth functionality
 * through context-specific interfaces for authentication, clients, URLs, and tokens.
 */
class OAuthPassport {

	/**
	 * Authentication context instance
	 *
	 * @var AuthenticationContext|null
	 */
	private static ?AuthenticationContext $auth_context = null;

	/**
	 * Client context instance
	 *
	 * @var ClientContext|null
	 */
	private static ?ClientContext $client_context = null;

	/**
	 * URL context instance
	 *
	 * @var UrlContext|null
	 */
	private static ?UrlContext $url_context = null;

	/**
	 * Token service instance
	 *
	 * @var TokenService|null
	 */
	private static ?TokenService $token_service = null;

	/**
	 * Get authentication context
	 *
	 * Returns the authentication context for managing user authentication,
	 * token validation, and scope verification operations.
	 *
	 * @return AuthenticationContext
	 */
	public static function auth(): AuthenticationContext {
		if ( null === self::$auth_context ) {
			self::$auth_context = new AuthenticationContext(
				ServiceContainer::getTokenService(),
				ServiceContainer::getScopeValidator()
			);
		}
		return self::$auth_context;
	}

	/**
	 * Get client context
	 *
	 * Returns the client context for managing OAuth client registration,
	 * configuration, and client credential operations.
	 *
	 * @return ClientContext
	 */
	public static function clients(): ClientContext {
		if ( null === self::$client_context ) {
			self::$client_context = new ClientContext(
				ServiceContainer::getClientRepository(),
				ServiceContainer::getTokenGenerator(),
				ServiceContainer::getClientSecretManager()
			);
		}
		return self::$client_context;
	}

	/**
	 * Get URL context
	 *
	 * Returns the URL context for generating OAuth endpoint URLs
	 * and managing routing for authorization and token endpoints.
	 *
	 * @return UrlContext
	 */
	public static function urls(): UrlContext {
		if ( null === self::$url_context ) {
			self::$url_context = new UrlContext();
		}
		return self::$url_context;
	}

	/**
	 * Get token service
	 *
	 * Returns the token service for handling token operations including
	 * token exchange, validation, refresh, and cleanup.
	 *
	 * @return TokenService
	 */
	public static function tokens(): TokenService {
		if ( null === self::$token_service ) {
			self::$token_service = ServiceContainer::getTokenService();
		}
		return self::$token_service;
	}

	/**
	 * Check if OAuth functionality is enabled
	 *
	 * Determines whether OAuth operations are currently enabled,
	 * allowing for dynamic enabling/disabling via filters.
	 *
	 * @return bool True if OAuth is enabled
	 */
	public static function isEnabled(): bool {
		return apply_filters( 'oauth_passport_enabled', true );
	}

	/**
	 * Get available OAuth scopes
	 *
	 * Returns all registered OAuth scopes with their descriptions,
	 * including both default and custom scopes.
	 *
	 * @return array Scope => description pairs
	 */
	public static function getAvailableScopes(): array {
		return ServiceContainer::getScopeValidator()->getAvailableScopes();
	}

	/**
	 * Get default OAuth scopes
	 *
	 * Returns the default scopes that are automatically granted
	 * when no specific scopes are requested.
	 *
	 * @return array Default scope names
	 */
	public static function getDefaultScopes(): array {
		// Use the static method from ScopeManager for default scopes
		return ScopeManager::get_default_scopes();
	}

	/**
	 * Clean up expired tokens
	 *
	 * Removes expired access tokens, refresh tokens, and authorization codes
	 * from the database to maintain optimal performance.
	 *
	 * @return int Number of tokens cleaned up
	 */
	public static function cleanupExpiredTokens(): int {
		return self::tokens()->cleanupExpiredTokens();
	}

	/**
	 * Reset all cached instances
	 *
	 * Clears all cached context instances and service container state.
	 * Primarily used for testing to ensure clean state between tests.
	 */
	public static function reset(): void {
		self::$auth_context = null;
		self::$client_context = null;
		self::$url_context = null;
		self::$token_service = null;
		ServiceContainer::clearInstances();
	}

	/**
	 * Set custom context instances
	 *
	 * Allows overriding context instances with custom implementations.
	 * Primarily used for testing with mock objects.
	 *
	 * @param string $context Context name ('auth', 'clients', 'urls', 'tokens')
	 * @param object $instance Context instance
	 */
	public static function setContext( string $context, object $instance ): void {
		switch ( $context ) {
			case 'auth':
				self::$auth_context = $instance;
				break;
			case 'clients':
				self::$client_context = $instance;
				break;
			case 'urls':
				self::$url_context = $instance;
				break;
			case 'tokens':
				self::$token_service = $instance;
				break;
		}
	}
}
