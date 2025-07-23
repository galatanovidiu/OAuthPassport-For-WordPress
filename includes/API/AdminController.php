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

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->namespace     = 'oauth-passport/v1';
		$this->rest_base     = 'admin';
		$this->oauth_schema  = new Schema();
		$this->scope_manager = new ScopeManager();
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
			$clients = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY created_at DESC', $table ) );

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
		$scopes       = $request->get_param( 'scopes' ) ? $request->get_param( 'scopes' ) : array( 'read', 'write' );

		if ( ! $client_name || ! $redirect_uri ) {
			return new WP_Error( 'missing_params', 'Client name and redirect URI are required', array( 'status' => 400 ) );
		}

		// Validate scopes.
		$available_scopes = array_keys( $this->scope_manager->get_available_scopes() );
		$scopes           = array_intersect( $scopes, $available_scopes );

		// Generate client credentials.
		$client_id     = 'oauth_passport_' . wp_generate_password( 32, false );
		$client_secret = wp_generate_password( 64, false );

		// Store client.
		global $wpdb;
		$table = $this->oauth_schema->get_clients_table_name();

		$result = $wpdb->insert(
			$table,
			array(
				'client_id'                 => $client_id,
				'client_secret'             => wp_hash( $client_secret ),
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
		$table = $this->oauth_schema->get_table_name();

		// Get active tokens.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT t.*, c.client_name, u.display_name 
				FROM %i t
				LEFT JOIN %i c ON t.client_id = c.client_id
				LEFT JOIN %i u ON t.user_id = u.ID
				WHERE t.token_type IN ('access', 'refresh') 
				AND t.expires_at > %s
				ORDER BY t.created_at DESC",
				$table,
				$this->oauth_schema->get_clients_table_name(),
				$wpdb->users,
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
				'default'     => array( 'read', 'write' ),
			),
		);
	}
}