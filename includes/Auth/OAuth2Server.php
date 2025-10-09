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
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Services\ClientService;
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
     * Token generator instance
     *
     * @var SecureTokenGenerator
     */
    private SecureTokenGenerator $token_generator;

    /**
     * Client repository instance
     *
     * @var ClientRepository
     */
    private ClientRepository $client_repository;

    /**
     * Client service instance
     *
     * @var ClientService
     */
    private ClientService $client_service;

    /**
     * Token repository instance
     *
     * @var TokenRepository
     */
    private TokenRepository $token_repository;

	/**
	 * Initialize OAuth 2.1 server
	 *
	 * Sets up all required components including database schema, discovery server,
	 * and admin interface. Initializes hooks if OAuth is enabled.
	 */
    public function __construct(
        Schema $schema,
        DiscoveryServer $discovery_server,
        ScopeManager $scope_manager,
        AuthorizationService $authorization_service,
        TokenService $token_service,
        ClientSecretManager $secret_manager,
        SecureTokenGenerator $token_generator,
        ClientRepository $client_repository,
        TokenRepository $token_repository,
        ClientService $client_service
    ) {
        $this->schema = $schema;
        $this->discovery_server = $discovery_server;
        $this->scope_manager = $scope_manager;
        $this->authorization_service = $authorization_service;
        $this->token_service = $token_service;
        $this->secret_manager = $secret_manager;
        $this->token_generator = $token_generator;
        $this->client_repository = $client_repository;
        $this->token_repository = $token_repository;
        $this->client_service = $client_service;

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
		if ( ! defined( 'OAUTH_PASSPORT_TEST_MODE' ) || ! constant( 'OAUTH_PASSPORT_TEST_MODE' ) ) {
			add_action( 'rest_api_init', array( $this, 'register_routes' ) );
			add_filter( 'rest_pre_serve_request', array( $this, 'add_cors_headers' ), 10, 4 );
		}

		// Hook into authentication filters only if not in test mode.
		if ( ! defined( 'OAUTH_PASSPORT_TEST_MODE' ) || ! constant( 'OAUTH_PASSPORT_TEST_MODE' ) ) {
			add_filter( 'determine_current_user', array( $this, 'authenticate_oauth' ), 20 );
			add_filter( 'rest_authentication_errors', array( $this, 'rest_authentication_errors' ), 20 );
			add_filter( 'rest_post_dispatch', array( $this, 'add_www_authenticate_to_response' ), 10, 3 );
		}

		// Add admin-post handler for OAuth authorization form
		add_action( 'admin_post_oauth_passport_authorize', array( $this, 'handle_authorization_form' ) );
		add_action( 'admin_post_nopriv_oauth_passport_authorize', array( $this, 'handle_authorization_form' ) );

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
				'permission_callback' => array( $this, 'authorize_permission_callback' ),
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
					'resource'              => array(
						'type'              => 'string',
						'format'            => 'uri',
						'validate_callback' => array( $this, 'validate_resource_param' ),
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

		try {
			$response = $this->client_service->registerClient( $params );
			return rest_ensure_response( $response );
		} catch ( \InvalidArgumentException $e ) {
			return new WP_Error(
				'invalid_client_metadata',
				$e->getMessage(),
				array( 'status' => 400 )
			);
		} catch ( \RuntimeException $e ) {
			return new WP_Error(
				'registration_failed',
				$e->getMessage(),
				array( 'status' => 500 )
			);
		}
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
		if ( ! $this->client_service->validateRegistrationToken( $token, $client_id ) ) {
			return new WP_Error(
				'invalid_token',
				'Invalid registration access token',
				array( 'status' => 401 )
			);
		}

		// Get client from database.
		$client_array = $this->client_repository->getClient( $client_id );
		if ( ! $client_array ) {
			return new WP_Error(
				'invalid_client',
				'Client not found',
				array( 'status' => 404 )
			);
		}
		
		// Convert array to object for compatibility
		$client = (object) $client_array;

		switch ( $method ) {
			case 'GET':
				return $this->get_client_configuration( $client );

			case 'PUT':
				return $this->update_client_configuration( $request, $client );

			case 'DELETE':
				$success = $this->client_service->deleteClient( $client_id );
				if ( $success ) {
					return rest_ensure_response( array( 'status' => 'deleted' ) );
				}
				return new WP_Error(
					'delete_failed',
					'Failed to delete client',
					array( 'status' => 500 )
				);

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
		$updated_client_array = $this->client_repository->getClient( $client->client_id );
		if ( ! $updated_client_array ) {
			return new WP_Error(
				'client_not_found',
				'Client not found after update',
				array( 'status' => 500 )
			);
		}
		return $this->get_client_configuration( (object) $updated_client_array );
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
		$resource       = $request->get_param( 'resource' ) ?? '';
		$default_scope  = implode( ' ', $this->scope_manager->getDefaultScopes() );
		$scope          = $request->get_param( 'scope' ) ?? $default_scope;


		// Validate required parameters.
		if ( empty( $client_id ) ) {
			return new WP_Error( 'invalid_request', 'Missing client_id parameter', array( 'status' => 400 ) );
		}

		// Validate client.
		$client = $this->client_service->getClient( $client_id );
		if ( ! $client ) {
			return new WP_Error( 'unauthorized_client', 'The client is not authorized to request an authorization code', array( 'status' => 400 ) );
		}


		// Get full client details for display.
		$client_details_array = $this->client_repository->getClient( $client_id );
		$client_details = $client_details_array ? (object) $client_details_array : null;

		// Validate redirect URI.
		if ( ! $this->client_service->validateRedirectUri( $client, $redirect_uri ) ) {
			return new WP_Error( 'invalid_redirect_uri', 'Invalid redirect URI', array( 'status' => 400 ) );
		}

		// Validate resource parameter if provided (RFC 8707)
		if ( ! empty( $resource ) && ! $this->client_service->validateResource( $client, $resource ) ) {
			return new WP_Error( 'invalid_target', 'Invalid or unauthorized resource parameter', array( 'status' => 400 ) );
		}

		// In test mode, return success for valid parameters (basic validation test)
		if ( defined( 'OAUTH_PASSPORT_TEST_MODE' ) && constant( 'OAUTH_PASSPORT_TEST_MODE' ) ) {
			return rest_ensure_response( array( 'status' => 'valid' ) );
		}

		// Check if user has already authorized this client.
		if ( $this->authorization_service->hasUserAuthorizedClient( get_current_user_id(), $client_id ) && empty( $_POST['oauth_action'] ) ) {
			// Skip consent page and generate code immediately.
			$this->generate_and_redirect_auth_code( $client_id, $redirect_uri, $code_challenge, $state, $scope, $resource );
			return;
		}

		// Handle form submission.
		if ( isset( $_POST['oauth_action'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ?? '' ) ), 'oauth_authorize' ) ) {
			if ( 'allow' === $_POST['oauth_action'] ) {
				// User approved - store authorization and generate code.
				$this->authorization_service->storeUserAuthorization( get_current_user_id(), $client_id );
				$this->generate_and_redirect_auth_code( $client_id, $redirect_uri, $code_challenge, $state, $scope, $resource );
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
		require_once OAUTH_PASSPORT_PATH . 'includes/Admin/Views/AuthorizationForm.php';
		\OAuthPassport\Admin\Views\render_authorization_form( $client_details, $redirect_uri, $code_challenge, $state, $scope, $this->scope_manager );
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
			return $this->oauth_error( 'invalid_request', 'Missing grant_type parameter', 400 );
		}

		try {
			// Handle refresh token grant
			if ( 'refresh_token' === $grant_type ) {
				$tokens = $this->token_service->refreshAccessToken(
					$params['refresh_token'] ?? '',
					$params['client_id'] ?? '',
					$params['client_secret'] ?? ''
				);
				return rest_ensure_response( $tokens );
			}

			// Handle authorization code grant
			if ( 'authorization_code' !== $grant_type ) {
				return $this->oauth_error( 'unsupported_grant_type', 'Only authorization_code and refresh_token grants are supported', 400 );
			}

			// For public clients using PKCE without client authentication,
			// client_id might not be sent. We can extract it from the authorization code.
			$client_id = $params['client_id'] ?? '';
			$code = $params['code'] ?? '';

			// If client_id is missing but we have a code, try to get client_id from the auth code
			if ( empty( $client_id ) && ! empty( $code ) ) {
				$auth_code = $this->token_repository->getAuthCode( $code );
				if ( $auth_code ) {
					$client_id = $auth_code->client_id;
				}
			}

			$tokens = $this->authorization_service->exchangeAuthorizationCode(
				$code,
				$client_id,
				$params['code_verifier'] ?? '',
				$params['resource'] ?? ''
			);

			return rest_ensure_response( $tokens );

		} catch ( \InvalidArgumentException $e ) {
			return $this->oauth_error( 'invalid_grant', $e->getMessage(), 400 );
		} catch ( \RuntimeException $e ) {
			return $this->oauth_error( 'server_error', $e->getMessage(), 500 );
		}
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
		$token_data = $this->token_service->validateAccessToken( $token );

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
					// Send WWW-Authenticate header for MCP discovery (RFC 9728)
					$this->send_www_authenticate_header();
					
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
	 * Clean up expired tokens
	 */
	public function cleanup_expired_tokens(): void {
		$this->schema->cleanup_expired_tokens();
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
		// @phpstan-ignore-next-line - WP_LOCAL_DEV is not a standard constant
		if ( defined( 'WP_LOCAL_DEV' ) && constant( 'WP_LOCAL_DEV' ) === true ) {
			return true;
		}

		// Allow filtering for custom development detection.
		return apply_filters( 'oauth_passport_is_development', false );
	}

	/**
	 * Generate authorization code and redirect
	 *
	 * @param string $client_id Client ID.
	 * @param string $redirect_uri Redirect URI.
	 * @param string $code_challenge PKCE code challenge.
	 * @param string $state State parameter.
	 * @param string $scope Requested scope.
	 * @param string $resource Target resource URI (RFC 8707).
	 */
	private function generate_and_redirect_auth_code( string $client_id, string $redirect_uri, string $code_challenge, ?string $state, string $scope, string $resource = '' ): void {
		try {
			// Generate authorization code via service with resource parameter
			$code = $this->authorization_service->generateAuthorizationCode(
				$client_id,
				get_current_user_id(),
				$code_challenge,
				$scope,
				$resource
			);

			// Redirect back to client
			$params = array( 'code' => $code );
			if ( $state ) {
				$params['state'] = $state;
			}

			wp_redirect( add_query_arg( $params, $redirect_uri ) );
			exit;
		} catch ( \Exception $e ) {
			wp_die( esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Authorization endpoint permission callback
	 *
	 * Redirects to login page if user is not authenticated, preserving the authorization request.
	 *
	 * @param WP_REST_Request $request The request object.
	 * @return bool|WP_Error True if user is logged in, redirect to login otherwise.
	 */
	public function authorize_permission_callback( WP_REST_Request $request ) {
		// Force WordPress to determine the current user from cookies
		// This is needed because the REST API permission callback runs before user determination
		wp_set_current_user( 0 ); // Reset first
		$current_user_id = apply_filters( 'determine_current_user', null );
		if ( $current_user_id ) {
			wp_set_current_user( $current_user_id );
		}

		// If user is authenticated, allow access
		if ( $current_user_id > 0 ) {
			return true;
		}

		// Build login URL with redirect back to authorization endpoint
		$params = $request->get_query_params();
		$current_url = add_query_arg( $params, rest_url( 'oauth-passport/v1/authorize' ) );
		$login_url = wp_login_url( $current_url );

		// Perform redirect to login page
		wp_redirect( $login_url );
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
		if ( $this->client_service->isLocalhostUri( $value ) ) {
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
	 * Validate resource parameter for REST API (RFC 8707)
	 *
	 * @param string          $value   The value submitted in the request.
	 * @param WP_REST_Request $request The request object.
	 * @param string          $param   The parameter name.
	 * @return bool|WP_Error True if valid, WP_Error otherwise.
	 */
	public function validate_resource_param( $value, $request, $param ) {
		// Empty resource is valid (optional parameter)
		if ( empty( $value ) ) {
			return true;
		}

		// Must not contain fragment
		if ( strpos( $value, '#' ) !== false ) {
			return new WP_Error(
				'rest_invalid_param',
				'Resource parameter must not contain fragment identifier',
				array( 'status' => 400 )
			);
		}

		$parsed = wp_parse_url( $value );

		// Must have scheme and host
		if ( empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return new WP_Error(
				'rest_invalid_param',
				'Resource parameter must be a valid absolute URI',
				array( 'status' => 400 )
			);
		}

		// Scheme must be http or https
		$scheme = strtolower( $parsed['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return new WP_Error(
				'rest_invalid_param',
				'Resource parameter must use http or https scheme',
				array( 'status' => 400 )
			);
		}

		return true;
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
	 * Send WWW-Authenticate header for 401 responses (RFC 9728)
	 *
	 * Per RFC 9728 (Protected Resource Metadata), servers MUST include
	 * WWW-Authenticate header in 401 responses to enable authorization
	 * server discovery for MCP clients.
	 *
	 * @return void
	 */
	private function send_www_authenticate_header(): void {
		// Only send if headers not already sent
		if ( headers_sent() ) {
			return;
		}

		$base_url = untrailingslashit( home_url() );
		$metadata_url = $base_url . '/.well-known/oauth-protected-resource';
		
		// Format per RFC 6750 and RFC 9728
		$header = sprintf(
			'Bearer realm="%s", as_uri="%s"',
			esc_attr( get_bloginfo( 'name' ) ),
			esc_url( $metadata_url )
		);
		
		header( 'WWW-Authenticate: ' . $header, false );
	}

	/**
	 * Add CORS headers to OAuth Passport REST API responses
	 *
	 * Enables MCP clients and other cross-origin clients to access OAuth endpoints.
	 * Only applies to oauth-passport namespace endpoints.
	 *
	 * @param bool              $served  Whether the request has already been served.
	 * @param \WP_REST_Response $result  Result to send to the client.
	 * @param \WP_REST_Request  $request Request used to generate the response.
	 * @param \WP_REST_Server   $server  Server instance.
	 * @return bool Whether the request was served.
	 */
	public function add_cors_headers( $served, $result, $request, $server ) {
		// Only handle oauth-passport namespace
		$route = $request->get_route();
		if ( strpos( $route, '/oauth-passport/' ) !== 0 ) {
			return $served;
		}

		// Add CORS headers for OAuth endpoints
		if ( ! headers_sent() ) {
			header( 'Access-Control-Allow-Origin: *' );
			header( 'Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS' );
			header( 'Access-Control-Allow-Headers: Content-Type, Authorization, mcp-protocol-version' );
			header( 'Access-Control-Expose-Headers: WWW-Authenticate' );
			header( 'Access-Control-Max-Age: 86400' );
		}

		// Handle OPTIONS preflight request
		if ( 'OPTIONS' === $request->get_method() ) {
			http_response_code( 204 );
			exit;
		}

		return $served;
	}

	/**
	 * Add WWW-Authenticate header to REST API 401 responses
	 *
	 * This filter ensures the WWW-Authenticate header is properly included
	 * in REST API responses for MCP client discovery.
	 *
	 * @param \WP_REST_Response $response Response object.
	 * @param \WP_REST_Server   $server   Server instance.
	 * @param \WP_REST_Request  $request  Request object.
	 * @return \WP_REST_Response Modified response.
	 */
	public function add_www_authenticate_to_response( $response, $server, $request ) {
		// Only add header to 401 responses
		if ( ! is_a( $response, 'WP_REST_Response' ) ) {
			return $response;
		}

		$status = $response->get_status();
		if ( 401 !== $status ) {
			return $response;
		}

		// Check if this is an OAuth-related error
		$data = $response->get_data();
		$is_oauth_error = false;

		if ( is_array( $data ) ) {
			// Check for oauth error codes
			$oauth_codes = array( 'oauth_invalid_token', 'rest_forbidden', 'rest_not_logged_in' );
			if ( isset( $data['code'] ) && in_array( $data['code'], $oauth_codes, true ) ) {
				$is_oauth_error = true;
			}
		} elseif ( is_wp_error( $data ) ) {
			$code = $data->get_error_code();
			if ( 'oauth_invalid_token' === $code || 'rest_forbidden' === $code ) {
				$is_oauth_error = true;
			}
		}

		// Also check if Bearer token was provided in request
		$auth_header = $request->get_header( 'authorization' );
		if ( ! empty( $auth_header ) && preg_match( '/Bearer\s+/i', $auth_header ) ) {
			$is_oauth_error = true;
		}

		// Add WWW-Authenticate header for OAuth-related 401s
		if ( $is_oauth_error ) {
			$base_url = untrailingslashit( home_url() );
			$metadata_url = $base_url . '/.well-known/oauth-protected-resource';
			
			$header = sprintf(
				'Bearer realm="%s", as_uri="%s"',
				esc_attr( get_bloginfo( 'name' ) ),
				esc_url( $metadata_url )
			);
			
			$response->header( 'WWW-Authenticate', $header );
		}

		return $response;
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
	 * Format an OAuth-compliant error payload.
	 */
	private function oauth_error( string $error, string $description, int $status ): WP_REST_Response {
		$response = new WP_REST_Response(
			array(
				'error'             => $error,
				'error_description' => $description,
			)
		);
		$response->set_status( $status );

		return $response;
	}

	/**
	 * Handle OAuth authorization form submission via admin-post
	 */
	public function handle_authorization_form(): void {
		// Verify nonce
		if ( ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ?? '' ) ), 'oauth_authorize' ) ) {
			wp_die( esc_html__( 'Security check failed', 'oauth-passport' ) );
		}

		// Get form data
		$client_id = sanitize_text_field( wp_unslash( $_POST['client_id'] ?? '' ) );
		$redirect_uri = esc_url_raw( wp_unslash( $_POST['redirect_uri'] ?? '' ) );
		$code_challenge = sanitize_text_field( wp_unslash( $_POST['code_challenge'] ?? '' ) );
		$state = sanitize_text_field( wp_unslash( $_POST['state'] ?? '' ) );
		$scope = sanitize_text_field( wp_unslash( $_POST['scope'] ?? '' ) );
		$resource = esc_url_raw( wp_unslash( $_POST['resource'] ?? '' ) );
		$oauth_action = sanitize_text_field( wp_unslash( $_POST['oauth_action'] ?? '' ) );


		// Validate client
		$client = $this->client_service->getClient( $client_id );
		if ( ! $client ) {
			wp_die( esc_html__( 'Invalid client', 'oauth-passport' ) );
		}

		// Validate redirect URI
		if ( ! $this->client_service->validateRedirectUri( $client, $redirect_uri ) ) {
			wp_die( esc_html__( 'Invalid redirect URI', 'oauth-passport' ) );
		}

		if ( 'allow' === $oauth_action ) {
			// User approved - store authorization and generate code with resource parameter
			$this->authorization_service->storeUserAuthorization( get_current_user_id(), $client_id );
			$this->generate_and_redirect_auth_code( $client_id, $redirect_uri, $code_challenge, $state, $scope, $resource );
		} else {
			// User denied - redirect with error
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
	}
} 
