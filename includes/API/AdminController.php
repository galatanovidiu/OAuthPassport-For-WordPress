<?php
/**
 * Admin API Controller for OAuth Passport
 *
 * Handles REST API endpoints for admin functionality.
 *
 * @package OAuthPassport
 * @subpackage API
 */

declare( strict_types=1 );

namespace OAuthPassport\API;

use OAuthPassport\Auth\Schema;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Services\ClientService;
use OAuthPassport\Services\TokenService;
use WP_REST_Controller;
use WP_REST_Server;
use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Class AdminController
 *
 * REST API controller for admin endpoints.
 */
class AdminController extends WP_REST_Controller {
	/**
	 * Schema instance
	 *
	 * @var Schema
	 */
	protected Schema $oauth_schema;

	/**
	 * Scope manager instance
	 *
	 * @var ScopeManager
	 */
	private ScopeManager $scope_manager;

	private SecureTokenGenerator $token_generator;

	private ClientSecretManager $secret_manager;

	private ClientService $client_service;

	private TokenService $token_service;

	/**
	 * Constructor
	 */
	public function __construct( 
		Schema $schema, 
		ScopeManager $scope_manager, 
		SecureTokenGenerator $token_generator, 
		ClientSecretManager $secret_manager,
		ClientService $client_service,
		TokenService $token_service
	) {
		$this->namespace       = 'oauth-passport/v1';
		$this->rest_base       = 'admin';
		$this->oauth_schema    = $schema;
		$this->scope_manager   = $scope_manager;
		$this->token_generator = $token_generator;
		$this->secret_manager  = $secret_manager;
		$this->client_service  = $client_service;
		$this->token_service   = $token_service;
	}

	/**
	 * Register routes
	 */
	public function register_routes(): void {
		// Clients endpoints.
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/clients',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_clients' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'create_client' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
					'args'                => $this->get_client_creation_args(),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/clients/(?P<client_id>[a-zA-Z0-9_]+)',
			array(
				array(
					'methods'             => WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_client' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
			)
		);

		// Client tokens revocation endpoint.
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/clients/(?P<client_id>[a-zA-Z0-9_]+)/tokens',
			array(
				array(
					'methods'             => WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'revoke_client_tokens' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
			)
		);

		// Tokens endpoints.
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/tokens',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_tokens' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
			)
		);

		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/tokens/(?P<token_id>\d+)',
			array(
				array(
					'methods'             => WP_REST_Server::DELETABLE,
					'callback'            => array( $this, 'delete_token' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
			)
		);

		// Manual token generation endpoint.
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/tokens/generate',
			array(
				array(
					'methods'             => WP_REST_Server::CREATABLE,
					'callback'            => array( $this, 'generate_manual_token' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
					'args'                => $this->get_token_generation_args(),
				),
			)
		);

		// OAuth endpoints list.
		register_rest_route(
			$this->namespace,
			'/' . $this->rest_base . '/endpoints',
			array(
				array(
					'methods'             => WP_REST_Server::READABLE,
					'callback'            => array( $this, 'get_endpoints' ),
					'permission_callback' => array( $this, 'check_admin_permissions' ),
				),
			)
		);
	}

	/**
	 * Check admin permissions
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return bool|WP_Error
	 */
	public function check_admin_permissions( WP_REST_Request $request ) {
		return current_user_can( 'manage_options' );
	}

	/**
	 * Get clients
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_clients( WP_REST_Request $request ) {
		try {
			global $wpdb;
			$table = $this->oauth_schema->get_clients_table_name();

			// Check if table exists.
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			if ( ! $table_exists ) {
				// Try to create tables.
				$this->oauth_schema->create_tables();
			}

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
				$clients = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY created_at DESC" );

			if ( is_wp_error( $clients ) ) {
				return new WP_Error( 'database_error', 'Failed to retrieve clients: ' . $wpdb->last_error, array( 'status' => 500 ) );
			}

			return new WP_REST_Response( $clients ? $clients : array(), 200 );
		} catch ( \Exception $e ) {
			return new WP_Error( 'server_error', 'Server error: ' . $e->getMessage(), array( 'status' => 500 ) );
		}
	}

	/**
	 * Create client
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function create_client( WP_REST_Request $request ) {
		$client_name  = sanitize_text_field( $request->get_param( 'client_name' ) );
		$redirect_uri = esc_url_raw( $request->get_param( 'redirect_uri' ) );
		$requested_scopes = $request->get_param( 'scopes' );
		$scopes = is_array( $requested_scopes ) ? $requested_scopes : $this->scope_manager->getDefaultScopes();

		if ( ! $client_name || ! $redirect_uri ) {
			return new WP_Error( 'missing_params', 'Client name and redirect URI are required', array( 'status' => 400 ) );
		}

		// Validate scopes.
		$available_scopes = array_keys( $this->scope_manager->getAvailableScopes() );
		$scopes           = array_values( array_intersect( $scopes, $available_scopes ) );
		if ( empty( $scopes ) ) {
			$scopes = $this->scope_manager->getDefaultScopes();
		}

		// Generate client credentials.
		$client_id     = $this->token_generator->generateClientId();
		$client_secret = $this->token_generator->generateClientSecret();
		$hashed_secret = $this->secret_manager->hashClientSecret( $client_secret );

		// Store client.
		global $wpdb;
		$table = $this->oauth_schema->get_clients_table_name();

		$result = $wpdb->insert(
			$table,
			array(
				'client_id'                 => $client_id,
				'client_secret_hash'        => $hashed_secret,
				'client_name'               => $client_name,
				'redirect_uris'             => wp_json_encode( array( $redirect_uri ) ),
				'grant_types'               => wp_json_encode( array( 'authorization_code' ) ),
				'response_types'            => wp_json_encode( array( 'code' ) ),
				'scope'                     => implode( ' ', $scopes ),
				'token_endpoint_auth_method' => 'client_secret_post',
				'client_id_issued_at'       => time(),
				'client_secret_expires_at'  => 0,
			)
		);

		if ( false === $result ) {
			return new WP_Error( 'database_error', 'Failed to create client', array( 'status' => 500 ) );
		}

		return new WP_REST_Response(
			array(
				'client_id'     => $client_id,
				'client_secret' => $client_secret,
				'client_name'   => $client_name,
				'redirect_uri'  => $redirect_uri,
				'scopes'        => $scopes,
			),
			201
		);
	}

	/**
	 * Delete client
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function delete_client( WP_REST_Request $request ) {
		$client_id = sanitize_text_field( $request->get_param( 'client_id' ) );

		if ( ! $client_id ) {
			return new WP_Error( 'missing_client_id', 'Client ID is required', array( 'status' => 400 ) );
		}

		global $wpdb;
		$clients_table = $this->oauth_schema->get_clients_table_name();
		$tokens_table  = $this->oauth_schema->get_table_name();

		// Delete all tokens for this client.
		$wpdb->delete( $tokens_table, array( 'client_id' => $client_id ) );

		// Delete client.
		$result = $wpdb->delete( $clients_table, array( 'client_id' => $client_id ) );

		if ( false === $result ) {
			return new WP_Error( 'database_error', 'Failed to delete client', array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'deleted' => true ), 200 );
	}

	/**
	 * Get tokens
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_tokens( WP_REST_Request $request ) {
		global $wpdb;
		$table = esc_sql( $this->oauth_schema->get_table_name() );
		$clients_table = esc_sql( $this->oauth_schema->get_clients_table_name() );
		$users_table = esc_sql( $wpdb->users );

		// Get active tokens.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT t.*, c.client_name, u.display_name 
				FROM {$table} t
				LEFT JOIN {$clients_table} c ON t.client_id = c.client_id
				LEFT JOIN {$users_table} u ON t.user_id = u.ID
				WHERE t.token_type IN ('access', 'refresh') 
				AND t.expires_at > %s
				ORDER BY t.created_at DESC",
				current_time( 'mysql' )
			)
		);

		if ( is_wp_error( $tokens ) ) {
			return new WP_Error( 'database_error', 'Failed to retrieve tokens', array( 'status' => 500 ) );
		}

		return new WP_REST_Response( $tokens ? $tokens : array(), 200 );
	}

	/**
	 * Delete token
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function delete_token( WP_REST_Request $request ) {
		$token_id = absint( $request->get_param( 'token_id' ) );

		if ( ! $token_id ) {
			return new WP_Error( 'missing_token_id', 'Token ID is required', array( 'status' => 400 ) );
		}

		global $wpdb;
		$table = $this->oauth_schema->get_table_name();

		$result = $wpdb->delete( $table, array( 'id' => $token_id ) );

		if ( false === $result ) {
			return new WP_Error( 'database_error', 'Failed to delete token', array( 'status' => 500 ) );
		}

		return new WP_REST_Response( array( 'deleted' => true ), 200 );
	}

	/**
	 * Get OAuth endpoints
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function get_endpoints( WP_REST_Request $request ) {
		$base_url = untrailingslashit( home_url() );

		$endpoints = array(
			'authorization_endpoint'         => rest_url( 'oauth-passport/v1/authorize' ),
			'token_endpoint'                 => rest_url( 'oauth-passport/v1/token' ),
			'registration_endpoint'          => rest_url( 'oauth-passport/v1/register' ),
			'discovery_endpoint'             => $base_url . '/.well-known/oauth-authorization-server',
			'resource_metadata_endpoint'     => $base_url . '/.well-known/oauth-protected-resource',
			'issuer'                         => $base_url,
			'scopes_supported'               => array_keys( $this->scope_manager->getAvailableScopes() ),
			'response_types_supported'       => array( 'code' ),
			'grant_types_supported'          => array( 'authorization_code', 'refresh_token' ),
			'code_challenge_methods_supported' => array( 'S256' ),
		);

		return new WP_REST_Response( $endpoints, 200 );
	}

	/**
	 * Generate manual token
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function generate_manual_token( WP_REST_Request $request ) {
		$client_id  = sanitize_text_field( $request->get_param( 'client_id' ) );
		$user_id    = absint( $request->get_param( 'user_id' ) );
		$scope      = sanitize_text_field( $request->get_param( 'scope' ) ?? 'read' );
		$resource   = esc_url_raw( $request->get_param( 'resource' ) ?? '' );
		$expires_in = absint( $request->get_param( 'expires_in' ) ?? 3600 );

		if ( ! $client_id || ! $user_id ) {
			return new WP_Error( 'missing_params', 'client_id and user_id are required', array( 'status' => 400 ) );
		}

		// Validate client exists
		if ( ! $this->client_service->validateClientForManualToken( $client_id ) ) {
			return new WP_Error( 'invalid_client', 'Client not found', array( 'status' => 404 ) );
		}

		// Validate user exists
		if ( ! get_user_by( 'id', $user_id ) ) {
			return new WP_Error( 'invalid_user', 'User not found', array( 'status' => 404 ) );
		}

		// Validate scope
		$valid_scopes = $this->scope_manager->validate( $scope );
		$scope_string = implode( ' ', $valid_scopes );

		try {
			// Generate tokens using TokenService with resource parameter
			$tokens = $this->token_service->issueTokens( $client_id, $user_id, $scope_string, $resource );

			$response_data = array(
				'access_token'  => $tokens['access_token'],
				'refresh_token' => $tokens['refresh_token'],
				'token_type'    => 'Bearer',
				'expires_in'    => $tokens['expires_in'],
				'scope'         => $tokens['scope'],
				'generated_at'  => current_time( 'mysql' ),
				'note'          => 'These tokens are shown only once. Store them securely.',
			);

			// Include resource if present (RFC 8707)
			if ( ! empty( $resource ) ) {
				$response_data['resource'] = $resource;
			}

			return new WP_REST_Response( $response_data, 201 );
		} catch ( \Exception $e ) {
			return new WP_Error( 'generation_failed', 'Failed to generate tokens: ' . $e->getMessage(), array( 'status' => 500 ) );
		}
	}

	/**
	 * Revoke all tokens for a client
	 *
	 * @param WP_REST_Request $request Request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function revoke_client_tokens( WP_REST_Request $request ) {
		$client_id = sanitize_text_field( $request->get_param( 'client_id' ) );

		if ( ! $client_id ) {
			return new WP_Error( 'missing_client_id', 'Client ID is required', array( 'status' => 400 ) );
		}

		try {
			$success = $this->client_service->revokeAllClientTokens( $client_id );
			
			return new WP_REST_Response(
				array(
					'revoked' => $success,
					'message' => $success ? 'All tokens revoked successfully' : 'No tokens to revoke',
				),
				200
			);
		} catch ( \Exception $e ) {
			return new WP_Error( 'revocation_failed', 'Failed to revoke tokens: ' . $e->getMessage(), array( 'status' => 500 ) );
		}
	}

	/**
	 * Get client creation arguments
	 *
	 * @return array
	 */
	private function get_client_creation_args(): array {
		return array(
			'client_name'  => array(
				'required'    => true,
				'type'        => 'string',
				'description' => 'Client name',
			),
			'redirect_uri' => array(
				'required'    => true,
				'type'        => 'string',
				'format'      => 'uri',
				'description' => 'Redirect URI',
			),
			'scopes'       => array(
				'required'    => false,
				'type'        => 'array',
				'items'       => array( 'type' => 'string' ),
				'description' => 'OAuth scopes',
				'default'     => $this->scope_manager->getDefaultScopes(),
			),
		);
	}

	/**
	 * Get token generation arguments
	 *
	 * @return array
	 */
	private function get_token_generation_args(): array {
		return array(
			'client_id'  => array(
				'required'    => true,
				'type'        => 'string',
				'description' => 'Client ID',
			),
			'user_id'    => array(
				'required'    => true,
				'type'        => 'integer',
				'description' => 'User ID',
			),
			'scope'      => array(
				'required'    => false,
				'type'        => 'string',
				'description' => 'OAuth scope (space-separated)',
				'default'     => 'read',
			),
			'resource'   => array(
				'required'    => false,
				'type'        => 'string',
				'format'      => 'uri',
				'description' => 'Target resource URI (RFC 8707)',
			),
			'expires_in' => array(
				'required'    => false,
				'type'        => 'integer',
				'description' => 'Token expiration in seconds',
				'default'     => 3600,
				'minimum'     => 300,
				'maximum'     => 86400,
			),
		);
	}
}
