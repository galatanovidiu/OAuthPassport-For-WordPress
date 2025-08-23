<?php
/**
 * URL Context
 *
 * Generates URLs for OAuth endpoints including authorization, token,
 * registration, and discovery endpoints with proper parameter handling.
 *
 * @package OAuthPassport
 * @subpackage Context
 */

declare( strict_types=1 );

namespace OAuthPassport\Context;

/**
 * Class UrlContext
 *
 * Provides OAuth endpoint URL generation with proper parameter handling
 * and context-aware routing for all OAuth 2.1 endpoints.
 */
class UrlContext {

	/**
	 * REST API namespace for OAuth endpoints
	 *
	 * @var string
	 */
	private string $namespace;

	/**
	 * Initialize URL context
	 *
	 * @param string $namespace REST API namespace for OAuth endpoints
	 */
	public function __construct( string $namespace = 'oauth-passport/v1' ) {
		$this->namespace = $namespace;
	}

	/**
	 * Get authorization URL
	 *
	 * Generates the OAuth authorization endpoint URL with optional query parameters.
	 * Automatically includes default response_type if not specified.
	 *
	 * @param array $params Query parameters for authorization request
	 * @return string Complete authorization URL with parameters
	 */
	public function getAuthorizationUrl( array $params = array() ): string {
		$defaults = array(
			'response_type' => 'code',
		);
		$params = wp_parse_args( $params, $defaults );

		return add_query_arg( $params, $this->getEndpointUrl( 'authorize' ) );
	}

	/**
	 * Get token endpoint URL
	 *
	 * Returns the OAuth token endpoint URL for token exchange operations.
	 *
	 * @return string Token endpoint URL
	 */
	public function getTokenUrl(): string {
		return $this->getEndpointUrl( 'token' );
	}

	/**
	 * Get client registration URL
	 *
	 * @return string Registration endpoint URL
	 */
	public function getRegistrationUrl(): string {
		return $this->getEndpointUrl( 'register' );
	}

	/**
	 * Get client configuration URL
	 *
	 * @param string $client_id Client ID
	 * @return string Client configuration URL
	 */
	public function getClientConfigurationUrl( string $client_id ): string {
		return $this->getEndpointUrl( 'register/' . $client_id );
	}

	/**
	 * Get JWKS endpoint URL
	 *
	 * @return string JWKS endpoint URL
	 */
	public function getJwksUrl(): string {
		return $this->getEndpointUrl( 'jwks' );
	}

	/**
	 * Get discovery endpoint URLs
	 *
	 * @return array Discovery endpoint URLs
	 */
	public function getDiscoveryUrls(): array {
		$base_url = untrailingslashit( home_url() );
		
		return array(
			'authorization_server' => $base_url . '/.well-known/oauth-authorization-server',
			'protected_resource' => $base_url . '/.well-known/oauth-protected-resource',
		);
	}

	/**
	 * Get all OAuth endpoint URLs
	 *
	 * @return array All endpoint URLs
	 */
	public function getAllEndpoints(): array {
		$discovery = $this->getDiscoveryUrls();
		
		return array(
			'authorization' => $this->getAuthorizationUrl(),
			'token' => $this->getTokenUrl(),
			'registration' => $this->getRegistrationUrl(),
			'jwks' => $this->getJwksUrl(),
			'discovery_authorization_server' => $discovery['authorization_server'],
			'discovery_protected_resource' => $discovery['protected_resource'],
		);
	}

	/**
	 * Build authorization URL with PKCE
	 *
	 * @param string $client_id Client ID
	 * @param string $redirect_uri Redirect URI
	 * @param string $code_challenge PKCE challenge
	 * @param string $state State parameter
	 * @param string $scope Requested scope
	 * @return string Complete authorization URL
	 */
	public function buildAuthorizationUrl(
		string $client_id,
		string $redirect_uri,
		string $code_challenge,
		string $state = '',
		string $scope = 'read write'
	): string {
		$params = array(
			'client_id' => $client_id,
			'redirect_uri' => $redirect_uri,
			'code_challenge' => $code_challenge,
			'code_challenge_method' => 'S256',
			'scope' => $scope,
		);

		if ( ! empty( $state ) ) {
			$params['state'] = $state;
		}

		return $this->getAuthorizationUrl( $params );
	}

	/**
	 * Check if URL is a valid OAuth redirect URI
	 *
	 * @param string $url URL to validate
	 * @return bool True if valid redirect URI
	 */
	public function isValidRedirectUri( string $url ): bool {
		// Basic URL validation
		if ( ! wp_http_validate_url( $url ) ) {
			// Allow localhost URLs for development
			if ( $this->isLocalhostUrl( $url ) ) {
				return true;
			}
			return false;
		}

		// Additional security checks could be added here
		return true;
	}

	/**
	 * Get endpoint URL
	 *
	 * @param string $endpoint Endpoint path
	 * @return string Full endpoint URL
	 */
	private function getEndpointUrl( string $endpoint ): string {
		return rest_url( $this->namespace . '/' . $endpoint );
	}

	/**
	 * Check if URL is localhost
	 *
	 * @param string $url URL to check
	 * @return bool True if localhost URL
	 */
	private function isLocalhostUrl( string $url ): bool {
		$parsed = wp_parse_url( $url );
		if ( ! $parsed || empty( $parsed['host'] ) ) {
			return false;
		}

		$host = strtolower( $parsed['host'] );
		$localhost_patterns = array( 'localhost', '127.0.0.1', '::1', '0.0.0.0' );

		foreach ( $localhost_patterns as $pattern ) {
			if ( $host === $pattern || str_starts_with( $host, $pattern . ':' ) ) {
				return true;
			}
		}

		return str_ends_with( $host, '.local' );
	}
}
