<?php
/**
 * Service Container
 *
 * Dependency injection container that manages service instances and their dependencies.
 * Provides singleton pattern implementation for OAuth service components.
 *
 * @package OAuthPassport
 * @subpackage Container
 */

declare( strict_types=1 );

namespace OAuthPassport\Container;

use OAuthPassport\Contracts\TokenGeneratorInterface;
use OAuthPassport\Contracts\ClientSecretManagerInterface;
use OAuthPassport\Contracts\TokenRepositoryInterface;
use OAuthPassport\Contracts\ClientRepositoryInterface;
use OAuthPassport\Contracts\ScopeValidatorInterface;

use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Services\TokenService;
use OAuthPassport\Context\AuthenticationContext;
use OAuthPassport\Context\ClientContext;
use OAuthPassport\Context\UrlContext;

/**
 * Class ServiceContainer
 *
 * Manages OAuth service instances using the singleton pattern.
 * Handles dependency injection and service resolution for all OAuth components.
 */
class ServiceContainer {

	/**
	 * Cached service instances
	 *
	 * @var array<string, object>
	 */
	private static array $instances = array();

	/**
	 * Get token generator instance
	 *
	 * Returns a singleton instance of the secure token generator for creating
	 * authorization codes, access tokens, and refresh tokens.
	 *
	 * @return TokenGeneratorInterface
	 */
	public static function getTokenGenerator(): TokenGeneratorInterface {
		if ( ! isset( self::$instances['token_generator'] ) ) {
			self::$instances['token_generator'] = new SecureTokenGenerator();
		}
		return self::$instances['token_generator'];
	}

	/**
	 * Get client secret manager instance
	 *
	 * Returns a singleton instance for managing OAuth client secrets,
	 * including generation, validation, and secure storage.
	 *
	 * @return ClientSecretManagerInterface
	 */
	public static function getClientSecretManager(): ClientSecretManagerInterface {
		if ( ! isset( self::$instances['client_secret_manager'] ) ) {
			self::$instances['client_secret_manager'] = new ClientSecretManager();
		}
		return self::$instances['client_secret_manager'];
	}

	/**
	 * Get scope validator instance
	 *
	 * Returns a singleton instance for validating OAuth scopes and managing
	 * scope permissions for authorization requests.
	 *
	 * @return ScopeValidatorInterface
	 */
	public static function getScopeValidator(): ScopeValidatorInterface {
		if ( ! isset( self::$instances['scope_validator'] ) ) {
			self::$instances['scope_validator'] = new ScopeManager();
		}
		return self::$instances['scope_validator'];
	}

	/**
	 * Get token repository instance
	 *
	 * Returns a singleton instance for managing token storage and retrieval,
	 * including access tokens, refresh tokens, and authorization codes.
	 *
	 * @return TokenRepositoryInterface
	 */
	public static function getTokenRepository(): TokenRepositoryInterface {
		if ( ! isset( self::$instances['token_repository'] ) ) {
			self::$instances['token_repository'] = new TokenRepository();
		}
		return self::$instances['token_repository'];
	}

	/**
	 * Get client repository instance
	 *
	 * Returns a singleton instance for managing OAuth client data,
	 * including client registration, validation, and configuration.
	 *
	 * @return ClientRepositoryInterface
	 */
	public static function getClientRepository(): ClientRepositoryInterface {
		if ( ! isset( self::$instances['client_repository'] ) ) {
			self::$instances['client_repository'] = new ClientRepository();
		}
		return self::$instances['client_repository'];
	}

	/**
	 * Get authorization service instance
	 *
	 * Returns a singleton instance that handles OAuth authorization flows,
	 * including authorization code generation and validation.
	 *
	 * @return AuthorizationService
	 */
	public static function getAuthorizationService(): AuthorizationService {
		if ( ! isset( self::$instances['authorization_service'] ) ) {
			self::$instances['authorization_service'] = new AuthorizationService(
				self::getTokenGenerator(),
				self::getTokenRepository(),
				self::getClientRepository(),
				self::getScopeValidator()
			);
		}
		return self::$instances['authorization_service'];
	}

	/**
	 * Get token service instance
	 *
	 * Returns a singleton instance that manages token operations,
	 * including token exchange, validation, and refresh.
	 *
	 * @return TokenService
	 */
	public static function getTokenService(): TokenService {
		if ( ! isset( self::$instances['token_service'] ) ) {
			self::$instances['token_service'] = new TokenService(
				self::getTokenGenerator(),
				self::getTokenRepository(),
				self::getClientRepository(),
				self::getClientSecretManager()
			);
		}
		return self::$instances['token_service'];
	}

	/**
	 * Set custom service instance
	 *
	 * Allows overriding service instances, primarily used for testing
	 * with mock objects or alternative implementations.
	 *
	 * @param string $key Service key
	 * @param object $instance Service instance
	 */
	public static function setInstance( string $key, object $instance ): void {
		self::$instances[ $key ] = $instance;
	}

	/**
	 * Clear all cached service instances
	 *
	 * Removes all cached instances, forcing fresh instantiation on next access.
	 * Primarily used for testing to ensure clean state between tests.
	 */
	public static function clearInstances(): void {
		self::$instances = array();
	}

	/**
	 * Get authentication context instance
	 *
	 * Returns a singleton instance that provides authentication-related
	 * operations and user context management.
	 *
	 * @return AuthenticationContext
	 */
	public static function getAuthenticationContext(): AuthenticationContext {
		if ( ! isset( self::$instances['authentication_context'] ) ) {
			self::$instances['authentication_context'] = new AuthenticationContext(
				self::getTokenService(),
				self::getScopeValidator()
			);
		}
		return self::$instances['authentication_context'];
	}

	/**
	 * Get client context instance
	 *
	 * Returns a singleton instance that provides client management
	 * operations including registration and configuration.
	 *
	 * @return ClientContext
	 */
	public static function getClientContext(): ClientContext {
		if ( ! isset( self::$instances['client_context'] ) ) {
			self::$instances['client_context'] = new ClientContext(
				self::getClientRepository(),
				self::getTokenGenerator(),
				self::getClientSecretManager()
			);
		}
		return self::$instances['client_context'];
	}

	/**
	 * Get URL context instance
	 *
	 * Returns a singleton instance that handles OAuth endpoint URL
	 * generation and routing management.
	 *
	 * @return UrlContext
	 */
	public static function getUrlContext(): UrlContext {
		if ( ! isset( self::$instances['url_context'] ) ) {
			self::$instances['url_context'] = new UrlContext();
		}
		return self::$instances['url_context'];
	}

	/**
	 * Check if service instance exists
	 *
	 * Determines whether a service instance has been cached for the given key.
	 *
	 * @param string $key Service key
	 * @return bool True if instance exists
	 */
	public static function hasInstance( string $key ): bool {
		return isset( self::$instances[ $key ] );
	}
}
