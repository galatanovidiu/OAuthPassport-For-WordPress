<?php
/**
 * OAuth 2.1 Server Implementation
 *
 * Core OAuth 2.1 server that handles authorization flows, token management,
 * and client registration according to RFC 6749 and RFC 8252 specifications.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use OAuthPassport\Container\ServiceContainer;
use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Services\TokenService;

/**
 * Class OAuth2Server
 *
 * Implements OAuth 2.1 authorization server with PKCE support, dynamic client
 * registration, and secure token management for WordPress integration.
 */
class OAuth2Server {
	/**
	 * OAuth server enabled state
	 *
	 * @var bool
	 */
	private bool $enabled = true;

	/**
	 * Database schema instance
	 *
	 * @var Schema
	 */
	private Schema $schema;

	/**
	 * Discovery server instance
	 *
	 * @var DiscoveryServer
	 */
	private DiscoveryServer $discovery_server;

	/**
	 * JWKS server instance
	 *
	 * @var JWKSServer
	 */
	private JWKSServer $jwks_server;

	/**
	 * Scope manager instance
	 *
	 * @var ScopeManager
	 */
	private ScopeManager $scope_manager;

	/**
	 * Admin interface instance
	 *
	 * @var AdminInterface|null
	 */
	private ?AdminInterface $admin_interface = null;

	/**
	 * Error logger instance
	 *
	 * @var ErrorLogger
	 */
	private ErrorLogger $error_logger;

	/**
	 * Authorization service instance
	 *
	 * @var AuthorizationService
	 */
	private AuthorizationService $authorization_service;

	/**
	 * Token service instance
	 *
	 * @var TokenService
	 */
	private TokenService $token_service;

	/**
	 * Client secret manager instance
	 *
	 * @var ClientSecretManager
	 */
	private ClientSecretManager $secret_manager;

	/**
	 * Initialize OAuth 2.1 server
	 *
	 * Sets up all required components including database schema, discovery server,
	 * JWKS server, and admin interface. Initializes hooks if OAuth is enabled.
	 */
	public function __construct() {
		$this->schema = new Schema();
		$this->discovery_server = new DiscoveryServer();
		$this->jwks_server = new JWKSServer();
		$this->scope_manager = new ScopeManager();
		$this->error_logger = new ErrorLogger();
		
		// Use dependency injection via service container
		$this->authorization_service = ServiceContainer::getAuthorizationService();
		$this->token_service = ServiceContainer::getTokenService();
		$this->secret_manager = new ClientSecretManager();

		// Initialize admin interface only in admin context.
		if ( is_admin() ) {
			$this->admin_interface = new AdminInterface();
		}

		// Check if OAuth is enabled.
		$this->enabled = apply_filters( 'oauth_passport_enabled', true );

		if ( $this->enabled ) {
			$this->init();
		}
	}

	/**
	 * Initialize OAuth server
	 */
	private function init(): void {
		// Set up database on activation.
		add_action( 'init', array( $this, 'maybe_create_tables' ), 5 );

		// Register REST routes only if not in test mode.
		if ( ! defined( 'OAUTH_PASSPORT_TEST_MODE' ) || ! OAUTH_PASSPORT_TEST_MODE ) {
			add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		}

		// Hook into authentication filters only if not in test mode.
		if ( ! defined( 'OAUTH_PASSPORT_TEST_MODE' ) || ! OAUTH_PASSPORT_TEST_MODE ) {
			add_filter( 'determine_current_user', array( $this, 'authenticate_oauth' ), 20 );
			add_filter( 'rest_authentication_errors', array( $this, 'rest_authentication_errors' ), 20 );
		}

		// Clean up expired tokens daily.
		if ( ! wp_next_scheduled( 'oauth_passport_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'oauth_passport_cleanup' );
		}
		add_action( 'oauth_passport_cleanup', array( $this, 'cleanup_expired_tokens' ) );
	}

	/**
	 * Create database tables if needed
	 */
	public function maybe_create_tables(): void {
		if ( ! $this->schema->table_exists() ) {
			$this->schema->create_tables();
		}
	}

	/**
	 * Register OAuth endpoints
	 */
	public function register_routes(): void {
		// Dynamic Client Registration endpoint (RFC 7591).
		register_rest_route(
			'oauth-passport/v1',
			'/register',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_client_registration' ),
				'permission_callback' => '__return_true',
			)
		);

		// Client configuration endpoint (RFC 7592).
		register_rest_route(
			'oauth-passport/v1',
			'/register/(?P<client_id>[a-zA-Z0-9_-]+)',
			array(
				'methods'             => array( 'GET', 'PUT', 'DELETE' ),
				'callback'            => array( $this, 'handle_client_configuration' ),
				'permission_callback' => '__return_true',
			)
		);

		// Authorization endpoint.
		register_rest_route(
			'oauth-passport/v1',
			'/authorize',
			array(
				'methods'             => array( 'GET', 'POST' ),
				'callback'            => array( $this, 'handle_authorize' ),
				'permission_callback' => 'is_user_logged_in',
				'args'                => array(
					'client_id'             => array(
						'required' => true,
						'type'     => 'string',
					),
					'redirect_uri'          => array(
						'required'          => true,
						'type'              => 'string',
						'validate_callback' => array( $this, 'validate_redirect_uri_param' ),
					),
					'code_challenge'        => array(
						'required' => true,
						'type'     => 'string',
					),
					'code_challenge_method' => array(
						'required' => true,
						'enum'     => array( 'S256' ),
					),
					'state'                 => array(
						'type' => 'string',
					),
				),
			)
		);

		// Token endpoint.
		register_rest_route(
			'oauth-passport/v1',
			'/token',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_token' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Handle dynamic client registration (RFC 7591)
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_client_registration( WP_REST_Request $request ) {
		$params = $request->get_json_params();

		// Validate required parameters.
		if ( empty( $params['client_name'] ) ) {
			return new WP_Error(
				'invalid_client_metadata',
				'client_name is required',
				array( 'status' => 400 )
			);
		}

		if ( empty( $params['redirect_uris'] ) || ! is_array( $params['redirect_uris'] ) ) {
			return new WP_Error(
				'invalid_redirect_uri',
				'redirect_uris must be a non-empty array',
				array( 'status' => 400 )
			);
		}

		// Validate all redirect URIs.
		foreach ( $params['redirect_uris'] as $uri ) {
			// Always allow localhost URLs.
			if ( $this->is_localhost_uri( $uri ) ) {
				continue;
			}
			
			if ( ! wp_http_validate_url( $uri ) ) {
				return new WP_Error(
					'invalid_redirect_uri',
					'Invalid redirect URI: ' . $uri,
					array( 'status' => 400 )
				);
			}
		}

		// Generate client credentials using secure token generator.
		$token_generator = ServiceContainer::getTokenGenerator();
		$secret_manager = ServiceContainer::getClientSecretManager();
		
		$client_id     = $token_generator->generateClientId();
		$client_secret = $token_generator->generateClientSecret();
		$issued_at     = time();
		
		$hashed_secret = $secret_manager->hashClientSecret( $client_secret );

		// Generate registration access token.
		$registration_token = $token_generator->generateRegistrationToken();

		// Prepare client metadata.
		$client_data = array(
			'client_id'                 => $client_id,
			'client_secret_hash'        => $hashed_secret,
			'client_name'               => sanitize_text_field( $params['client_name'] ),
			'redirect_uris'             => wp_json_encode( $params['redirect_uris'] ),
			'grant_types'               => wp_json_encode( $params['grant_types'] ?? array( 'authorization_code' ) ),
			'response_types'            => wp_json_encode( $params['response_types'] ?? array( 'code' ) ),
			'scope'                     => $params['scope'] ?? implode( ' ', ScopeManager::get_default_scopes() ),
			'contacts'                  => wp_json_encode( $params['contacts'] ?? array() ),
			'logo_uri'                  => esc_url_raw( $params['logo_uri'] ?? '' ),
			'client_uri'                => esc_url_raw( $params['client_uri'] ?? '' ),
			'policy_uri'                => esc_url_raw( $params['policy_uri'] ?? '' ),
			'tos_uri'                   => esc_url_raw( $params['tos_uri'] ?? '' ),
			'jwks_uri'                  => esc_url_raw( $params['jwks_uri'] ?? '' ),
			'token_endpoint_auth_method' => sanitize_text_field( $params['token_endpoint_auth_method'] ?? 'client_secret_post' ),
			'registration_access_token' => wp_hash( $registration_token ),
			'registration_client_uri'   => rest_url( 'oauth-passport/v1/register/' . $client_id ),
			'client_id_issued_at'       => $issued_at,
			'client_secret_expires_at'  => 0, // Never expires.
		);

		// Store client in database.
		global $wpdb;
		$table = $this->schema->get_clients_table_name();

		$result = $wpdb->insert( $table, $client_data );

		if ( false === $result ) {
			return new WP_Error(
				'registration_failed',
				'Failed to register client',
				array( 'status' => 500 )
			);
		}

		// Store registration token for later validation.
		$this->store_registration_token( $registration_token, $client_id );

		// Return client information (RFC 7591 compliant response).
		$response = array(
			'client_id'                     => $client_id,
			'client_secret'                 => $client_secret,
			'client_id_issued_at'           => $issued_at,
			'client_secret_expires_at'      => 0,
			'registration_access_token'     => $registration_token,
			'registration_client_uri'       => $client_data['registration_client_uri'],
			'client_name'                   => $params['client_name'],
			'redirect_uris'                 => $params['redirect_uris'],
			'grant_types'                   => $params['grant_types'] ?? array( 'authorization_code' ),
			'response_types'                => $params['response_types'] ?? array( 'code' ),
			'scope'                         => $params['scope'] ?? implode( ' ', ScopeManager::get_default_scopes() ),
			'token_endpoint_auth_method'    => $params['token_endpoint_auth_method'] ?? 'client_secret_post',
		);

		// Add optional fields if provided.
		$optional_fields = array( 'contacts', 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri', 'jwks_uri' );
		foreach ( $optional_fields as $field ) {
			if ( ! empty( $params[ $field ] ) ) {
				$response[ $field ] = $params[ $field ];
			}
		}

		return rest_ensure_response( $response );
	}

	/**
	 * Handle client configuration endpoint (RFC 7592)
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_client_configuration( WP_REST_Request $request ) {
		$client_id = $request->get_param( 'client_id' );
		$method    = $request->get_method();

		// Validate registration access token.
		$auth_header = $request->get_header( 'authorization' );
		if ( ! preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			return new WP_Error(
				'invalid_token',
				'Registration access token required',
				array( 'status' => 401 )
			);
		}

		$token = $matches[1];

		// Verify token is valid for this client.
		if ( ! $this->validate_registration_token( $token, $client_id ) ) {
			return new WP_Error(
				'invalid_token',
				'Invalid registration access token',
				array( 'status' => 401 )
			);
		}

		// Get client from database.
		$client = $this->get_client_from_db( $client_id );
		if ( ! $client ) {
			return new WP_Error(
				'invalid_client',
				'Client not found',
				array( 'status' => 404 )
			);
		}

		switch ( $method ) {
			case 'GET':
				return $this->get_client_configuration( $client );

			case 'PUT':
				return $this->update_client_configuration( $request, $client );

			case 'DELETE':
				return $this->delete_client( $client_id );

			default:
				return new WP_Error(
					'method_not_allowed',
					'Method not allowed',
					array( 'status' => 405 )
				);
		}
	}

	/**
	 * Get client configuration
	 *
	 * @param object $client Client data.
	 * @return WP_REST_Response
	 */
	private function get_client_configuration( $client ): WP_REST_Response {
		$response = array(
			'client_id'                  => $client->client_id,
			'client_name'                => $client->client_name,
			'redirect_uris'              => json_decode( $client->redirect_uris ),
			'grant_types'                => json_decode( $client->grant_types ),
			'response_types'             => json_decode( $client->response_types ),
			'scope'                      => $client->scope,
			'token_endpoint_auth_method' => $client->token_endpoint_auth_method,
			'client_id_issued_at'        => intval( $client->client_id_issued_at ),
			'client_secret_expires_at'   => intval( $client->client_secret_expires_at ),
		);

		// Add optional fields.
		$optional_fields = array( 'contacts', 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri', 'jwks_uri' );
		foreach ( $optional_fields as $field ) {
			if ( ! empty( $client->$field ) ) {
				$value = ( 'contacts' === $field ) ? json_decode( $client->$field ) : $client->$field;
				if ( ! empty( $value ) ) {
					$response[ $field ] = $value;
				}
			}
		}

		return rest_ensure_response( $response );
	}

	/**
	 * Update client configuration
	 *
	 * @param WP_REST_Request $request The request object.
	 * @param object          $client Current client data.
	 * @return WP_REST_Response|WP_Error
	 */
	private function update_client_configuration( WP_REST_Request $request, $client ) {
		$params = $request->get_json_params();

		// Prepare update data.
		$update_data = array();

		// Update allowed fields.
		$allowed_fields = array(
			'client_name',
			'redirect_uris',
			'grant_types',
			'response_types',
			'scope',
			'contacts',
			'logo_uri',
			'client_uri',
			'policy_uri',
			'tos_uri',
			'jwks_uri',
			'token_endpoint_auth_method',
		);

		foreach ( $allowed_fields as $field ) {
			if ( isset( $params[ $field ] ) ) {
				if ( in_array( $field, array( 'redirect_uris', 'grant_types', 'response_types', 'contacts' ), true ) ) {
					$update_data[ $field ] = wp_json_encode( $params[ $field ] );
				} elseif ( in_array( $field, array( 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri', 'jwks_uri' ), true ) ) {
					$update_data[ $field ] = esc_url_raw( $params[ $field ] );
				} else {
					$update_data[ $field ] = sanitize_text_field( $params[ $field ] );
				}
			}
		}

		if ( empty( $update_data ) ) {
			return new WP_Error(
				'invalid_request',
				'No valid fields to update',
				array( 'status' => 400 )
			);
		}

		// Update client in database.
		global $wpdb;
		$table = $this->schema->get_clients_table_name();

		$result = $wpdb->update(
			$table,
			$update_data,
			array( 'client_id' => $client->client_id )
		);

		if ( false === $result ) {
			return new WP_Error(
				'update_failed',
				'Failed to update client',
				array( 'status' => 500 )
			);
		}

		// Get updated client.
		$updated_client = $this->get_client_from_db( $client->client_id );
		if ( ! $updated_client ) {
			return null;
		}
		return $this->get_client_configuration( $updated_client );
	}

	/**
	 * Delete client
	 *
	 * @param string $client_id Client ID.
	 * @return WP_REST_Response|WP_Error
	 */
	private function delete_client( string $client_id ) {
		global $wpdb;
		$clients_table = $this->schema->get_clients_table_name();
		$tokens_table  = $this->schema->get_table_name();

		// Delete all tokens for this client.
		$wpdb->delete(
			$tokens_table,
			array( 'client_id' => $client_id )
		);

		// Delete client.
		$result = $wpdb->delete(
			$clients_table,
			array( 'client_id' => $client_id )
		);

		if ( false === $result ) {
			return new WP_Error(
				'delete_failed',
				'Failed to delete client',
				array( 'status' => 500 )
			);
		}

		return rest_ensure_response( array( 'status' => 'deleted' ) );
	}

	/**
	 * Store registration token
	 *
	 * @param string $token Registration token.
	 * @param string $client_id Client ID.
	 */
	private function store_registration_token( string $token, string $client_id ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'registration',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => 0, // System token.
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + 86400 * 365 ), // 1 year.
			)
		);
	}

	/**
	 * Validate registration token
	 *
	 * @param string $token Token value.
	 * @param string $client_id Expected client ID.
	 * @return bool
	 */
	private function validate_registration_token( string $token, string $client_id ): bool {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// Get all active registration tokens for this client to prevent timing attacks
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT token_value, client_id FROM %i 
				WHERE token_type = 'registration' 
				AND client_id = %s
				AND expires_at > %s",
				$table,
				$client_id,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		// Use timing-safe comparison to find matching token
		foreach ( $tokens as $stored_token ) {
			if ( SecurityUtils::validateToken( $token, $stored_token->token_value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get client from database
	 *
	 * @param string $client_id Client ID.
	 * @return object|null
	 */
	private function get_client_from_db( string $client_id ): ?object {
		global $wpdb;
		$table = $this->schema->get_clients_table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				'SELECT * FROM %i WHERE client_id = %s',
				$table,
				$client_id
			)
		);
	}

	/**
	 * Handle authorization request
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return void|WP_Error|WP_REST_Response
	 */
	public function handle_authorize( WP_REST_Request $request ) {
		$client_id      = $request->get_param( 'client_id' );
		$redirect_uri   = $request->get_param( 'redirect_uri' );
		$code_challenge = $request->get_param( 'code_challenge' );
		$state          = $request->get_param( 'state' );
		$scope          = $request->get_param( 'scope' ) ?? implode( ' ', ScopeManager::get_default_scopes() );

		// Validate required parameters.
		if ( empty( $client_id ) ) {
			return new WP_Error( 'invalid_request', 'Missing client_id parameter', array( 'status' => 400 ) );
		}

		// Validate client.
		$client = $this->get_client( $client_id );
		if ( ! $client ) {
			return new WP_Error( 'invalid_client', 'Invalid client', array( 'status' => 400 ) );
		}

		// Get full client details for display.
		$client_details = $this->get_client_from_db( $client_id );

		// Validate redirect URI.
		if ( ! $this->validate_redirect_uri( $client, $redirect_uri ) ) {
			return new WP_Error( 'invalid_redirect_uri', 'Invalid redirect URI', array( 'status' => 400 ) );
		}

		// In test mode, return success for valid parameters (basic validation test)
		if ( defined( 'OAUTH_PASSPORT_TEST_MODE' ) && OAUTH_PASSPORT_TEST_MODE ) {
			return rest_ensure_response( array( 'status' => 'valid' ) );
		}

		// Check if user has already authorized this client.
		if ( $this->has_user_authorized_client( get_current_user_id(), $client_id ) && empty( $_POST['oauth_action'] ) ) {
			// Skip consent page and generate code immediately.
			$this->generate_and_redirect_auth_code( $client_id, $redirect_uri, $code_challenge, $state, $scope );
			return;
		}

		// Handle form submission.
		if ( isset( $_POST['oauth_action'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ?? '' ) ), 'oauth_authorize' ) ) {
			if ( 'allow' === $_POST['oauth_action'] ) {
				// User approved - store authorization and generate code.
				$this->store_user_authorization( get_current_user_id(), $client_id );
				$this->generate_and_redirect_auth_code( $client_id, $redirect_uri, $code_challenge, $state, $scope );
			} else {
				// User denied - redirect with error.
				$params = array(
					'error'             => 'access_denied',
					'error_description' => 'The user denied the authorization request',
				);
				if ( $state ) {
					$params['state'] = $state;
				}
				wp_redirect( add_query_arg( $params, $redirect_uri ) );
				exit;
			}
			return;
		}

		// Show authorization consent page.
		$this->show_authorization_page( $client_details, $redirect_uri, $code_challenge, $state, $scope );
	}

	/**
	 * Handle token request
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_token( WP_REST_Request $request ) {
		$params = $request->get_json_params();
		if ( ! $params ) {
			$params = $request->get_body_params();
		}

		$grant_type = $params['grant_type'] ?? '';

		// Check for required grant_type parameter
		if ( empty( $grant_type ) ) {
			return new WP_Error(
				'invalid_request',
				'Missing grant_type parameter',
				array( 'status' => 400 )
			);
		}

		// Handle refresh token grant.
		if ( 'refresh_token' === $grant_type ) {
			return $this->handle_refresh_token( $request );
		}

		// Handle authorization code grant.
		if ( 'authorization_code' !== $grant_type ) {
			return new WP_Error(
				'unsupported_grant_type',
				'Only authorization_code and refresh_token grants are supported',
				array( 'status' => 400 )
			);
		}

		// Get auth code.
		$auth_code = $this->get_auth_code( $params['code'] ?? '' );

		if ( ! $auth_code ) {
			return new WP_Error(
				'invalid_grant',
				'Invalid or expired authorization code',
				array( 'status' => 400 )
			);
		}

		// Validate PKCE.
		if ( ! PKCEValidator::validate( $auth_code->code_challenge, $params['code_verifier'] ?? '' ) ) {
			return new WP_Error(
				'invalid_grant',
				'Invalid PKCE verifier',
				array( 'status' => 400 )
			);
		}

		// Validate client.
		$client = $this->get_client( $params['client_id'] ?? '' );
		if ( ! $client ) {
			return new WP_Error(
				'invalid_client',
				'Invalid client',
				array( 'status' => 401 )
			);
		}

		// For public clients using PKCE, client_secret is optional.
		// Only validate client_secret if it's provided.
		if ( ! empty( $params['client_secret'] ) && ! $this->verify_client_secret( $client, $params['client_secret'] ) ) {
			return new WP_Error(
				'invalid_client',
				'Invalid client credentials',
				array( 'status' => 401 )
			);
		}

		// Generate access token.
		$access_token = $this->generate_token( 'access' );

		// Generate refresh token.
		$refresh_token = $this->generate_token( 'refresh' );

		// Store access token (expires in 1 hour).
		$this->store_access_token( $access_token, $auth_code->client_id, (int) $auth_code->user_id );

		// Store refresh token (expires in 30 days).
		$this->store_refresh_token( $refresh_token, $auth_code->client_id, (int) $auth_code->user_id );

		// Delete used auth code.
		$this->delete_auth_code( (int) $auth_code->id );

		return rest_ensure_response(
			array(
				'access_token'  => $access_token,
				'refresh_token' => $refresh_token,
				'token_type'    => 'Bearer',
				'expires_in'    => 3600,
				'scope'         => 'read write',
			)
		);
	}

	/**
	 * Handle refresh token grant
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	private function handle_refresh_token( WP_REST_Request $request ) {
		$params = $request->get_json_params();
		if ( ! $params ) {
			$params = $request->get_body_params();
		}

		// Validate refresh token.
		$refresh_token_value = $params['refresh_token'] ?? '';
		if ( empty( $refresh_token_value ) ) {
			return new WP_Error(
				'invalid_request',
				'refresh_token parameter is required',
				array( 'status' => 400 )
			);
		}

		// Get refresh token from database.
		global $wpdb;
		$table = $this->schema->get_table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$refresh_token = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i 
				WHERE token_type = 'refresh' 
				AND token_value = %s 
				AND expires_at > %s",
				$table,
				$refresh_token_value,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		if ( ! $refresh_token ) {
			return new WP_Error(
				'invalid_grant',
				'Invalid or expired refresh token',
				array( 'status' => 400 )
			);
		}

		// Validate client.
		$client = $this->get_client( $params['client_id'] ?? '' );
		if ( ! $client || $client['client_id'] !== $refresh_token->client_id ) {
			return new WP_Error(
				'invalid_client',
				'Invalid client for this refresh token',
				array( 'status' => 401 )
			);
		}

		// Verify client secret if provided.
		if ( ! empty( $params['client_secret'] ) && ! $this->verify_client_secret( $client, $params['client_secret'] ) ) {
			return new WP_Error(
				'invalid_client',
				'Invalid client credentials',
				array( 'status' => 401 )
			);
		}

		// Generate new access token.
		$new_access_token = $this->generate_token( 'access' );

		// Generate new refresh token (rotation for security).
		$new_refresh_token = $this->generate_token( 'refresh' );

		// Store new access token.
		$this->store_access_token( $new_access_token, $refresh_token->client_id, (int) $refresh_token->user_id, $refresh_token->scope );

		// Store new refresh token.
		$this->store_refresh_token( $new_refresh_token, $refresh_token->client_id, (int) $refresh_token->user_id, $refresh_token->scope );

		// Delete old refresh token.
		$wpdb->delete(
			$table,
			array( 'id' => $refresh_token->id )
		);

		return rest_ensure_response(
			array(
				'access_token'  => $new_access_token,
				'refresh_token' => $new_refresh_token,
				'token_type'    => 'Bearer',
				'expires_in'    => 3600,
				'scope'         => $refresh_token->scope,
			)
		);
	}

	/**
	 * Authenticate OAuth token
	 *
	 * @param int|false $user_id Current user ID or false.
	 * @return int|false User ID if authenticated, false otherwise.
	 */
	public function authenticate_oauth( $user_id ) {
		// Skip if already authenticated.
		if ( ! empty( $user_id ) ) {
			return $user_id;
		}

		// Check for Bearer token in Authorization header.
		$auth_header = '';
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = $_SERVER['HTTP_AUTHORIZATION'];
		} elseif ( isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) {
			$auth_header = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
		}

		if ( empty( $auth_header ) || ! preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			return $user_id;
		}

		$token = $matches[1];

		// Skip if it looks like a JWT (has dots).
		if ( str_contains( $token, '.' ) ) {
			return $user_id;
		}

		// Validate OAuth token.
		$token_data = $this->validate_access_token( $token );

		if ( $token_data ) {
			return (int) $token_data->user_id;
		}

		return $user_id;
	}

	/**
	 * Check for OAuth authentication errors in REST context
	 *
	 * @param WP_Error|null|bool $result Current error state.
	 * @return WP_Error|null|bool Modified error state.
	 */
	public function rest_authentication_errors( $result ) {
		// Pass through existing errors.
		if ( ! empty( $result ) ) {
			return $result;
		}

		// Check if OAuth was attempted but failed.
		$auth_header = '';
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth_header = $_SERVER['HTTP_AUTHORIZATION'];
		}

		if ( ! empty( $auth_header ) && preg_match( '/Bearer\s+(.+)/i', $auth_header, $matches ) ) {
			$token = $matches[1];
			
			// Skip JWT tokens.
			if ( ! str_contains( $token, '.' ) ) {
				// OAuth token was provided but user is not authenticated.
				if ( ! is_user_logged_in() ) {
					return new WP_Error(
						'oauth_invalid_token',
						'The access token is invalid or expired',
						array( 'status' => 401 )
					);
				}
			}
		}

		return $result;
	}

	/**
	 * Get client by ID
	 *
	 * @param string $client_id Client ID.
	 * @return array|null Client data or null if not found.
	 */
	private function get_client( string $client_id ): ?array {
		// First check database for dynamically registered clients.
		$db_client = $this->get_client_from_db( $client_id );

		if ( $db_client ) {
			return array(
				'client_id'           => $db_client->client_id,
				'client_secret_hash'  => $db_client->client_secret_hash,
				'redirect_uris'       => json_decode( $db_client->redirect_uris, true ),
			);
		}

		// Fall back to statically configured clients.
		$clients = get_option( 'oauth_passport_clients', array() );
		return $clients[ $client_id ] ?? null;
	}

	/**
	 * Verify client secret
	 *
	 * @param array  $client Client data.
	 * @param string $provided_secret Provided secret.
	 * @return bool
	 */
	private function verify_client_secret( array $client, string $provided_secret ): bool {
		// If client has no secret (public client), it can't be verified against a provided secret.
		if ( empty( $client['client_secret_hash'] ) ) {
			return false;
		}

		// Use the secure client secret manager for verification
		$secret_manager = \OAuthPassport\Container\ServiceContainer::getClientSecretManager();
		$verification_result = $secret_manager->verifyClientSecret( $provided_secret, $client['client_secret_hash'] );

		// Check if hash needs rehashing and update if needed
		if ( $verification_result && $secret_manager->needsRehash( $client['client_secret_hash'] ) ) {
			$client_repository = \OAuthPassport\Container\ServiceContainer::getClientRepository();
			$new_hash = $secret_manager->hashClientSecret( $provided_secret );
			$client_repository->rehashClientSecret( $client['client_id'] ?? '', $new_hash );
		}

		return $verification_result;
	}

	/**
	 * Rehash client secret with new secure algorithm
	 *
	 * @param string $client_id Client ID.
	 * @param string $plain_secret Plain text secret.
	 */
	private function rehash_client_secret( string $client_id, string $plain_secret ): void {
		if ( empty( $client_id ) ) {
			return;
		}

		try {
			$new_hash = $this->secret_manager->hashClientSecret( $plain_secret );
			
			global $wpdb;
			$table = $this->schema->get_clients_table_name();
			
			$wpdb->update(
				$table,
				array( 'client_secret_hash' => $new_hash ),
				array( 'client_id' => $client_id )
			);
		} catch ( \Exception $e ) {
			// Log error but don't fail the authentication
			error_log( 'OAuth Passport: Failed to rehash client secret: ' . $e->getMessage() );
		}
	}

	/**
	 * Validate redirect URI
	 *
	 * @param array  $client Client data.
	 * @param string $redirect_uri Redirect URI to validate.
	 * @return bool
	 */
	private function validate_redirect_uri( array $client, string $redirect_uri ): bool {
		// For dynamically registered clients.
		if ( isset( $client['redirect_uris'] ) && is_array( $client['redirect_uris'] ) ) {
			return in_array( $redirect_uri, $client['redirect_uris'], true );
		}

		// For statically configured clients (backward compatibility).
		return isset( $client['redirect_uri'] ) && $client['redirect_uri'] === $redirect_uri;
	}

	/**
	 * Generate random token
	 *
	 * @param string $prefix Token prefix.
	 * @return string Generated token.
	 */
	private function generate_token( string $prefix = 'oauth' ): string {
		$token_generator = \OAuthPassport\Container\ServiceContainer::getTokenGenerator();
		switch ( $prefix ) {
			case 'access':
				return $token_generator->generateAccessToken();
			case 'refresh':
				return $token_generator->generateRefreshToken();
			case 'code':
			case 'auth':
				return $token_generator->generateAuthCode();
			case 'registration':
				return $token_generator->generateRegistrationToken();
			default:
				// For any other prefix, generate an access token as fallback
				return $token_generator->generateAccessToken();
		}
	}

	/**
	 * Store authorization code
	 *
	 * @param string $code Authorization code.
	 * @param string $client_id Client ID.
	 * @param int    $user_id User ID.
	 * @param string $code_challenge PKCE challenge.
	 */
	private function store_auth_code( string $code, string $client_id, int $user_id, string $code_challenge ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'     => 'code',
				'token_value'    => $code,
				'client_id'      => $client_id,
				'user_id'        => $user_id,
				'code_challenge' => $code_challenge,
				'expires_at'     => gmdate( 'Y-m-d H:i:s', time() + 300 ), // 5 minutes.
			)
		);
	}

	/**
	 * Get authorization code
	 *
	 * @param string $code Authorization code.
	 * @return object|null Code data or null if not found.
	 */
	private function get_auth_code( string $code ): ?object {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		return $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i 
				WHERE token_type = 'code' 
				AND token_value = %s 
				AND expires_at > %s",
				$table,
				$code,
				gmdate( 'Y-m-d H:i:s' )
			)
		);
	}

	/**
	 * Delete authorization code
	 *
	 * @param int $code_id Code ID.
	 */
	private function delete_auth_code( int $code_id ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->delete(
			$table,
			array( 'id' => $code_id )
		);
	}

	/**
	 * Store access token
	 *
	 * @param string $token Access token.
	 * @param string $client_id Client ID.
	 * @param int    $user_id User ID.
	 * @param string $scope Token scope.
	 */
	private function store_access_token( string $token, string $client_id, int $user_id, string $scope = 'read write' ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'access',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + 3600 ), // 1 hour.
			)
		);
	}

	/**
	 * Store refresh token
	 *
	 * @param string $token Refresh token.
	 * @param string $client_id Client ID.
	 * @param int    $user_id User ID.
	 * @param string $scope Token scope.
	 */
	private function store_refresh_token( string $token, string $client_id, int $user_id, string $scope = 'read write' ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'refresh',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => $user_id,
				'scope'       => $scope,
				'expires_at'  => gmdate( 'Y-m-d H:i:s', time() + 86400 * 30 ), // 30 days.
			)
		);
	}

	/**
	 * Validate access token
	 *
	 * @param string $token Access token.
	 * @return object|null Token data or null if invalid.
	 */
	private function validate_access_token( string $token ): ?object {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// Get all active access tokens to prevent timing attacks
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT user_id, client_id, token_value FROM %i 
				WHERE token_type = 'access' 
				AND expires_at > %s",
				$table,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		// Use timing-safe comparison to find matching token
		foreach ( $tokens as $stored_token ) {
			if ( SecurityUtils::validateToken( $token, $stored_token->token_value ) ) {
				return $stored_token;
			}
		}

		return null;
	}

	/**
	 * Get token information for introspection
	 *
	 * @param string $token The token to introspect.
	 * @return object|false Token information or false if not found.
	 */
	private function get_token_info( string $token ) {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$token_data = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM %i WHERE token_value = %s AND expires_at > %s",
				$table,
				$token,
				gmdate( 'Y-m-d H:i:s' )
			)
		);

		if ( ! $token_data ) {
			return false;
		}

		return $token_data;
	}

	/**
	 * Revoke a token
	 *
	 * @param string $token The token to revoke.
	 * @return bool True if token was revoked, false if not found.
	 */
	private function revoke_token( string $token ): bool {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// Delete token from database (works for both access and refresh tokens since they all use token_value)
		$result = $wpdb->delete(
			$table,
			array(
				'token_value' => $token,
			)
		);

		return $result > 0;
	}

	/**
	 * Clean up expired tokens
	 */
	public function cleanup_expired_tokens(): void {
		$this->schema->cleanup_expired_tokens();
	}

	/**
	 * Check if URI is a localhost URL
	 *
	 * @param string $uri URI to check.
	 * @return bool
	 */
	private function is_localhost_uri( string $uri ): bool {
		$host = wp_parse_url( $uri, PHP_URL_HOST );
		if ( ! $host ) {
			return false;
		}

		$localhost_patterns = array(
			'localhost',
			'127.0.0.1',
			'::1',
			'0.0.0.0',
		);

		foreach ( $localhost_patterns as $pattern ) {
			if ( $host === $pattern || str_starts_with( $host, $pattern . ':' ) ) {
				return true;
			}
		}

		// Check for *.local domains.
		if ( str_ends_with( $host, '.local' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check if running in development environment
	 *
	 * @return bool
	 */
	private function is_development_environment(): bool {
		// Check WP_ENVIRONMENT_TYPE (WordPress 5.5+).
		if ( function_exists( 'wp_get_environment_type' ) ) {
			return in_array( wp_get_environment_type(), array( 'local', 'development' ), true );
		}

		// Check WP_DEBUG.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			return true;
		}

		// Check for common development indicators.
		// phpstan-ignore-next-line
		if ( defined( 'WP_LOCAL_DEV' ) && \WP_LOCAL_DEV ) {
			return true;
		}

		// Allow filtering for custom development detection.
		return apply_filters( 'oauth_passport_is_development', false );
	}

	/**
	 * Check if user has already authorized client
	 *
	 * @param int    $user_id User ID.
	 * @param string $client_id Client ID.
	 * @return bool
	 */
	private function has_user_authorized_client( int $user_id, string $client_id ): bool {
		$authorizations = get_user_meta( $user_id, 'oauth_passport_authorizations', true );
		if ( ! is_array( $authorizations ) ) {
			return false;
		}
		return in_array( $client_id, $authorizations, true );
	}

	/**
	 * Store user authorization for client
	 *
	 * @param int    $user_id User ID.
	 * @param string $client_id Client ID.
	 */
	private function store_user_authorization( int $user_id, string $client_id ): void {
		$authorizations = get_user_meta( $user_id, 'oauth_passport_authorizations', true );
		if ( ! is_array( $authorizations ) ) {
			$authorizations = array();
		}
		if ( ! in_array( $client_id, $authorizations, true ) ) {
			$authorizations[] = $client_id;
			update_user_meta( $user_id, 'oauth_passport_authorizations', $authorizations );
		}
	}

	/**
	 * Generate authorization code and redirect
	 *
	 * @param string $client_id Client ID.
	 * @param string $redirect_uri Redirect URI.
	 * @param string $code_challenge PKCE code challenge.
	 * @param string $state State parameter.
	 * @param string $scope Requested scope.
	 */
	private function generate_and_redirect_auth_code( string $client_id, string $redirect_uri, string $code_challenge, ?string $state, string $scope ): void {
		// Generate authorization code.
		$code = $this->generate_token( 'auth' );

		// Store auth code with scope (expires in 5 minutes).
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'     => 'code',
				'token_value'    => $code,
				'client_id'      => $client_id,
				'user_id'        => get_current_user_id(),
				'code_challenge' => $code_challenge,
				'scope'          => $scope,
				'expires_at'     => gmdate( 'Y-m-d H:i:s', time() + 300 ), // 5 minutes.
			)
		);

		// Redirect back to client.
		$params = array( 'code' => $code );
		if ( $state ) {
			$params['state'] = $state;
		}

		wp_redirect( add_query_arg( $params, $redirect_uri ) );
		exit;
	}

	/**
	 * Show authorization consent page
	 *
	 * @param object $client Client details.
	 * @param string $redirect_uri Redirect URI.
	 * @param string $code_challenge PKCE code challenge.
	 * @param string $state State parameter.
	 * @param string $scope Requested scope.
	 */
	private function show_authorization_page( ?object $client, string $redirect_uri, string $code_challenge, ?string $state, string $scope ): void {
		// Prepare scope descriptions.
		$scope_descriptions = $this->scope_manager->format_scopes_for_display( $scope );
		$scopes = explode( ' ', $scope );

		// Get current user.
		$current_user = wp_get_current_user();

		// Set proper headers.
		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );
		
		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1">
			<title><?php esc_html_e( 'Authorize Application', 'oauth-passport' ); ?> - <?php bloginfo( 'name' ); ?></title>
			<?php wp_admin_css( 'login', true ); ?>
			<style>
				body {
					background: #f0f0f1;
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
				}
				.oauth-container {
					margin: 50px auto;
					max-width: 500px;
					background: #fff;
					box-shadow: 0 1px 3px rgba(0,0,0,.13);
					padding: 40px;
				}
				.oauth-header {
					text-align: center;
					margin-bottom: 40px;
				}
				.oauth-logo {
					max-width: 84px;
					margin: 0 auto 20px;
				}
				.oauth-title {
					font-size: 24px;
					margin: 0 0 10px;
					color: #3c434a;
				}
				.oauth-subtitle {
					color: #646970;
					font-size: 14px;
				}
				.oauth-client-info {
					background: #f6f7f7;
					border: 1px solid #c3c4c7;
					padding: 20px;
					margin-bottom: 30px;
					border-radius: 4px;
				}
				.oauth-client-name {
					font-weight: 600;
					font-size: 16px;
					margin-bottom: 10px;
				}
				.oauth-permissions {
					margin-bottom: 30px;
				}
				.oauth-permissions-title {
					font-weight: 600;
					margin-bottom: 15px;
					color: #1d2327;
				}
				.oauth-permission-list {
					list-style: none;
					padding: 0;
					margin: 0;
				}
				.oauth-permission-item {
					padding: 10px 0;
					padding-left: 30px;
					position: relative;
					color: #50575e;
				}
				.oauth-permission-item:before {
					content: "✓";
					position: absolute;
					left: 0;
					color: #00a32a;
					font-weight: bold;
				}
				.oauth-actions {
					display: flex;
					gap: 10px;
					justify-content: center;
				}
				.oauth-button {
					padding: 10px 30px;
					font-size: 14px;
					border-radius: 3px;
					border: 1px solid;
					cursor: pointer;
					text-decoration: none;
					transition: all 0.3s;
				}
				.oauth-button-primary {
					background: #2271b1;
					border-color: #2271b1;
					color: #fff;
				}
				.oauth-button-primary:hover {
					background: #135e96;
					border-color: #135e96;
				}
				.oauth-button-secondary {
					background: #f0f0f1;
					border-color: #c3c4c7;
					color: #2c3338;
				}
				.oauth-button-secondary:hover {
					background: #e5e5e5;
				}
				.oauth-user-info {
					text-align: center;
					margin-bottom: 20px;
					color: #646970;
					font-size: 14px;
				}
				.oauth-warning {
					background: #fcf9e8;
					border: 1px solid #dfd8c2;
					padding: 15px;
					margin-bottom: 20px;
					border-radius: 4px;
					color: #50575e;
					font-size: 14px;
				}
			</style>
		</head>
		<body>
			<div class="oauth-container">
				<div class="oauth-header">
					<div class="oauth-logo">
						<?php
						$custom_logo_id = get_theme_mod( 'custom_logo' );
						if ( $custom_logo_id ) {
							echo wp_get_attachment_image( $custom_logo_id, 'thumbnail' );
						} else {
							echo '<img src="' . esc_url( includes_url( 'images/w-logo-blue.png' ) ) . '" alt="WordPress">';
						}
						?>
					</div>
					<h1 class="oauth-title"><?php esc_html_e( 'Authorize Application', 'oauth-passport' ); ?></h1>
					<p class="oauth-subtitle"><?php esc_html_e( 'An application is requesting access to your account', 'oauth-passport' ); ?></p>
				</div>

				<div class="oauth-user-info">
					<?php
					printf(
						/* translators: %s: username */
						esc_html__( 'Logged in as %s', 'oauth-passport' ),
						'<strong>' . esc_html( $current_user->user_login ) . '</strong>'
					);
					?>
				</div>

				<div class="oauth-client-info">
					<div class="oauth-client-name">
						<?php echo esc_html( $client->client_name ?? __( 'Unknown Application', 'oauth-passport' ) ); ?>
					</div>
					<?php if ( ! empty( $client->client_uri ) ) : ?>
						<div class="oauth-client-uri">
							<a href="<?php echo esc_url( $client->client_uri ); ?>" target="_blank" rel="noopener noreferrer">
								<?php echo esc_html( wp_parse_url( $client->client_uri, PHP_URL_HOST ) ?: $client->client_uri ); ?>
							</a>
						</div>
					<?php endif; ?>
				</div>

				<div class="oauth-permissions">
					<div class="oauth-permissions-title"><?php esc_html_e( 'This application will be able to:', 'oauth-passport' ); ?></div>
					<ul class="oauth-permission-list">
						<?php
						$available_scopes = $this->scope_manager->get_available_scopes();
						foreach ( $scopes as $scope_key ) {
							if ( isset( $available_scopes[ $scope_key ] ) ) {
								echo '<li class="oauth-permission-item">' . esc_html( $available_scopes[ $scope_key ] ) . '</li>';
							}
						}
						?>
					</ul>
				</div>

				<div class="oauth-warning">
					<?php esc_html_e( 'Make sure you trust this application before authorizing. You can revoke access at any time from your account settings.', 'oauth-passport' ); ?>
				</div>

				<form method="post" action="<?php echo esc_url( rest_url( 'oauth-passport/v1/authorize' ) ); ?>">
					<?php wp_nonce_field( 'oauth_authorize' ); ?>
					<input type="hidden" name="client_id" value="<?php echo esc_attr( sanitize_text_field( wp_unslash( $_GET['client_id'] ?? '' ) ) ); ?>">
					<input type="hidden" name="redirect_uri" value="<?php echo esc_attr( $redirect_uri ); ?>">
					<input type="hidden" name="code_challenge" value="<?php echo esc_attr( $code_challenge ); ?>">
					<input type="hidden" name="code_challenge_method" value="S256">
					<input type="hidden" name="state" value="<?php echo esc_attr( $state ?? '' ); ?>">
					<input type="hidden" name="scope" value="<?php echo esc_attr( $scope ); ?>">

					<div class="oauth-actions">
						<button type="submit" name="oauth_action" value="allow" class="oauth-button oauth-button-primary">
							<?php esc_html_e( 'Authorize', 'oauth-passport' ); ?>
						</button>
						<button type="submit" name="oauth_action" value="deny" class="oauth-button oauth-button-secondary">
							<?php esc_html_e( 'Deny', 'oauth-passport' ); ?>
						</button>
					</div>
				</form>
			</div>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Validate redirect URI parameter for REST API
	 *
	 * @param string          $value   The value submitted in the request.
	 * @param WP_REST_Request $request The request object.
	 * @param string          $param   The parameter name.
	 * @return bool|WP_Error True if valid, WP_Error otherwise.
	 */
	public function validate_redirect_uri_param( $value, $request, $param ) {
		// Always allow localhost URLs.
		if ( $this->is_localhost_uri( $value ) ) {
			return true;
		}

		// Otherwise, use WordPress's URL validation.
		if ( wp_http_validate_url( $value ) ) {
			return true;
		}

		return new WP_Error(
			'rest_invalid_param',
			sprintf( 'Invalid %s parameter.', $param ),
			array( 'status' => 400 )
		);
	}

	/**
	 * Check if OAuth server is enabled
	 *
	 * @return bool
	 */
	public function is_enabled(): bool {
		return $this->enabled;
	}

	/**
	 * Handle authorization request (wrapper for handle_authorize)
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_authorization_request( WP_REST_Request $request ) {
		return $this->handle_authorize( $request );
	}

	/**
	 * Handle token request (wrapper for handle_token)
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_token_request( WP_REST_Request $request ) {
		return $this->handle_token( $request );
	}

	/**
	 * Handle token revocation
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_token_revocation( WP_REST_Request $request ) {
		$params = $request->get_json_params();
		if ( ! $params ) {
			$params = $request->get_body_params();
		}

		$token = $params['token'] ?? '';
		if ( empty( $token ) ) {
			return new WP_Error(
				'invalid_request',
				'Missing token parameter',
				array( 'status' => 400 )
			);
		}

		// Revoke the token
		$this->revoke_token( $token );

		return rest_ensure_response( array( 'revoked' => true ) );
	}

	/**
	 * Handle token introspection
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_token_introspection( WP_REST_Request $request ) {
		$params = $request->get_json_params();
		if ( ! $params ) {
			$params = $request->get_body_params();
		}

		$token = $params['token'] ?? '';
		if ( empty( $token ) ) {
			return new WP_Error(
				'invalid_request',
				'Missing token parameter',
				array( 'status' => 400 )
			);
		}

		// Get token info
		$token_info = $this->get_token_info( $token );
		
		if ( ! $token_info ) {
			return rest_ensure_response( array( 'active' => false ) );
		}

		// Check if token is expired
		$is_active = strtotime( $token_info->expires_at ) > time();

		$response = array(
			'active' => $is_active,
		);

		if ( $is_active ) {
			$response['client_id'] = $token_info->client_id;
			$response['scope'] = $token_info->scope;
			$response['exp'] = strtotime( $token_info->expires_at );
		}

		return rest_ensure_response( $response );
	}

	/**
	 * Handle discovery request
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_discovery_request( WP_REST_Request $request ) {
		return $this->discovery_server->handle_request( $request );
	}

	/**
	 * Handle JWKS request
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return WP_REST_Response|WP_Error
	 */
	public function handle_jwks_request( WP_REST_Request $request ) {
		return $this->jwks_server->handle_request( $request );
	}
} 