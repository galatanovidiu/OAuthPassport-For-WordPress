<?php
/**
 * OAuth Discovery Server for OAuth Passport
 *
 * Implements RFC 8414 (OAuth 2.0 Authorization Server Metadata) and
 * RFC 9728 (OAuth 2.0 Protected Resource Metadata)
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use OAuthPassport\OAuthPassport;

/**
 * Class DiscoveryServer
 *
 * Handles OAuth discovery endpoints for automatic client configuration.
 */
class DiscoveryServer {
	/**
	 * Initialize discovery server
	 */
	public function __construct() {
		// Hook into parse_request to handle .well-known paths.
		add_action( 'parse_request', array( $this, 'handle_well_known_requests' ) );

		// Add rewrite rules on init.
		add_action( 'init', array( $this, 'add_rewrite_rules' ) );
	}

	/**
	 * Add rewrite rules for .well-known endpoints
	 */
	public function add_rewrite_rules(): void {
		add_rewrite_rule(
			'^\.well-known/oauth-authorization-server/?$',
			'index.php?well_known_oauth=authorization-server',
			'top'
		);

		add_rewrite_rule(
			'^\.well-known/oauth-protected-resource/?$',
			'index.php?well_known_oauth=protected-resource',
			'top'
		);

		// Add query vars.
		add_filter(
			'query_vars',
			function ( $vars ) {
				$vars[] = 'well_known_oauth';
				return $vars;
			}
		);

		// Flush rewrite rules if our option is not set.
		if ( '1' !== get_option( 'oauth_passport_rewrite_rules_flushed' ) ) {
			flush_rewrite_rules();
			update_option( 'oauth_passport_rewrite_rules_flushed', '1' );
		}
	}

	/**
	 * Handle well-known requests
	 *
	 * @param \WP $wp WordPress object.
	 */
	public function handle_well_known_requests( \WP $wp ): void {
		if ( ! isset( $wp->query_vars['well_known_oauth'] ) ) {
			return;
		}

		$endpoint = $wp->query_vars['well_known_oauth'];

		switch ( $endpoint ) {
			case 'authorization-server':
				$this->handle_authorization_server_metadata();
				break;
			case 'protected-resource':
				$this->handle_protected_resource_metadata();
				break;
			default:
				return;
		}

		exit;
	}

	/**
	 * Handle OAuth Authorization Server Metadata endpoint (RFC 8414)
	 */
	private function handle_authorization_server_metadata(): void {
		$base_url = untrailingslashit( home_url() );

		$metadata = array(
			'issuer'                                => $base_url,
			'authorization_endpoint'                => rest_url( 'oauth-passport/v1/authorize' ),
			'token_endpoint'                        => rest_url( 'oauth-passport/v1/token' ),
			'registration_endpoint'                 => rest_url( 'oauth-passport/v1/register' ),
			'jwks_uri'                              => rest_url( 'oauth-passport/v1/jwks' ),
			'scopes_supported'                      => array_keys( OAuthPassport::getAvailableScopes() ),
			'response_types_supported'              => array( 'code' ),
			'grant_types_supported'                 => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported' => array( 'client_secret_post', 'client_secret_basic' ),
			'code_challenge_methods_supported'      => array( 'S256' ),
		);

		// Allow filtering of metadata.
		$metadata = apply_filters( 'oauth_passport_authorization_server_metadata', $metadata );

		// Send JSON response.
		$this->send_json_response( $metadata );
	}

	/**
	 * Handle Protected Resource Metadata endpoint (RFC 9728)
	 */
	private function handle_protected_resource_metadata(): void {
		$base_url = untrailingslashit( home_url() );

		$metadata = array(
			'resource'                 => $base_url,
			'authorization_servers'    => array( $base_url ),
			'scopes_supported'         => array_keys( OAuthPassport::getAvailableScopes() ),
			'bearer_methods_supported' => array( 'header' ),
			'jwks_uri'                 => rest_url( 'oauth-passport/v1/jwks' ),
		);

		// Allow filtering of metadata.
		$metadata = apply_filters( 'oauth_passport_protected_resource_metadata', $metadata );

		// Send JSON response.
		$this->send_json_response( $metadata );
	}

	/**
	 * Handle discovery request (for REST API compatibility)
	 *
	 * @param \WP_REST_Request $request The request object.
	 * @return array Authorization server metadata.
	 */
	public function handle_request( \WP_REST_Request $request ): array {
		$base_url = untrailingslashit( home_url() );

		$metadata = array(
			'issuer'                                => $base_url,
			'authorization_endpoint'                => rest_url( 'oauth-passport/v1/authorize' ),
			'token_endpoint'                        => rest_url( 'oauth-passport/v1/token' ),
			'registration_endpoint'                 => rest_url( 'oauth-passport/v1/register' ),
			'jwks_uri'                              => rest_url( 'oauth-passport/v1/jwks' ),
			'scopes_supported'                      => array_keys( OAuthPassport::getAvailableScopes() ),
			'response_types_supported'              => array( 'code' ),
			'grant_types_supported'                 => array( 'authorization_code', 'refresh_token' ),
			'token_endpoint_auth_methods_supported' => array( 'client_secret_post', 'client_secret_basic' ),
			'code_challenge_methods_supported'      => array( 'S256' ),
		);

		// Allow filtering of metadata.
		return apply_filters( 'oauth_passport_authorization_server_metadata', $metadata );
	}

	/**
	 * Send JSON response
	 *
	 * @param array $data Response data.
	 */
	private function send_json_response( array $data ): void {
		// Set CORS headers for discovery endpoints.
		header( 'Access-Control-Allow-Origin: *' );
		header( 'Access-Control-Allow-Methods: GET, OPTIONS' );
		header( 'Access-Control-Allow-Headers: Content-Type' );

		// Handle OPTIONS request.
		if ( isset( $_SERVER['REQUEST_METHOD'] ) && 'OPTIONS' === $_SERVER['REQUEST_METHOD'] ) {
			http_response_code( 204 );
			exit;
		}

		// Send JSON response.
		header( 'Content-Type: application/json; charset=utf-8' );
		http_response_code( 200 );

		// Pretty print for easier debugging.
		echo wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
	}
}
