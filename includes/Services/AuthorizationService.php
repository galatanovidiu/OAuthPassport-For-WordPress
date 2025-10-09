<?php
/**
 * Authorization Service
 *
 * Manages OAuth authorization flow operations including authorization code
 * generation, validation, and PKCE challenge verification.
 *
 * @package OAuthPassport
 * @subpackage Services
 */

declare( strict_types=1 );

namespace OAuthPassport\Services;

use OAuthPassport\Auth\PKCEValidator;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Repositories\TokenRepository;

/**
 * Class AuthorizationService
 *
 * Provides OAuth authorization flow operations including code generation,
 * validation, and scope-based access control with PKCE support.
 */
class AuthorizationService {

	/**
	 * Token generator
	 *
	 * @var SecureTokenGenerator
	 */
	private SecureTokenGenerator $token_generator;

	/**
	 * Token repository
	 *
	 * @var TokenRepository
	 */
	private TokenRepository $token_repository;

	/**
	 * Client repository
	 *
	 * @var ClientRepository
	 */
	private ClientRepository $client_repository;

	/**
	 * Scope manager
	 *
	 * @var ScopeManager
	 */
	private ScopeManager $scope_manager;

	/**
	 * Initialize authorization service
	 *
     * @param SecureTokenGenerator $token_generator Service for generating authorization codes
     * @param TokenRepository      $token_repository Repository for token storage and retrieval
     * @param ClientRepository     $client_repository Repository for client validation
     * @param ScopeManager         $scope_manager Service for scope validation and filtering
     */
    public function __construct(
        SecureTokenGenerator $token_generator,
        TokenRepository $token_repository,
        ClientRepository $client_repository,
        ScopeManager $scope_manager
    ) {
        $this->token_generator = $token_generator;
        $this->token_repository = $token_repository;
        $this->client_repository = $client_repository;
        $this->scope_manager = $scope_manager;
	}

	/**
	 * Generate authorization code
	 *
	 * Creates a new authorization code for the OAuth flow with client validation,
	 * scope filtering based on user capabilities, and PKCE challenge storage.
	 *
	 * @param string $client_id Client ID requesting authorization
	 * @param int    $user_id User ID granting authorization
	 * @param string $code_challenge PKCE code challenge for security
	 * @param string $scope Requested OAuth scopes
	 * @param string $resource Target resource URI (RFC 8707)
	 * @return string Generated authorization code
	 * @throws \Exception If generation fails or client is invalid
	 */
	public function generateAuthorizationCode( string $client_id, int $user_id, string $code_challenge, string $scope, string $resource = '' ): string {
		// Validate client exists
		$client = $this->client_repository->getClient( $client_id );
		if ( ! $client ) {
			throw new \InvalidArgumentException( 'Invalid client ID' );
		}

		// Validate and filter scopes
        $valid_scopes = $this->scope_manager->validate( $scope );
        $filtered_scopes = $this->scope_manager->filterForUser( $valid_scopes, $user_id );
		$final_scope = implode( ' ', $filtered_scopes );

		// Generate authorization code
		$auth_code = $this->token_generator->generateAuthCode();

		// Store authorization code (expires in 5 minutes)
		$success = $this->token_repository->storeAuthCode(
			$auth_code,
			$client_id,
			$user_id,
			$code_challenge,
			$final_scope,
			$resource,
			300
		);

		if ( ! $success ) {
			throw new \RuntimeException( 'Failed to store authorization code' );
		}

		return $auth_code;
	}

	/**
	 * Validate authorization code and exchange for tokens
	 *
	 * @param string $code Authorization code
	 * @param string $client_id Client ID
	 * @param string $code_verifier PKCE verifier
	 * @param string $resource Resource parameter from token request (RFC 8707)
	 * @return array Token data
	 * @throws \Exception If validation fails
	 */
	public function exchangeAuthorizationCode( string $code, string $client_id, string $code_verifier, string $resource = '' ): array {
		// Get authorization code
		$auth_code = $this->token_repository->getAuthCode( $code );
		if ( ! $auth_code ) {
			throw new \InvalidArgumentException( 'Invalid or expired authorization code' );
		}

		// Validate client matches
		if ( $auth_code->client_id !== $client_id ) {
			error_log( sprintf(
				'[OAuth Passport] Client ID mismatch - Expected: "%s", Got: "%s"',
				$auth_code->client_id,
				$client_id
			) );
			throw new \InvalidArgumentException( 'Client ID mismatch' );
		}

		// Validate resource parameter matches authorization code (RFC 8707)
		$auth_code_resource = $auth_code->resource ?? '';
		if ( ! empty( $resource ) || ! empty( $auth_code_resource ) ) {
			if ( $resource !== $auth_code_resource ) {
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					error_log( sprintf(
						'[OAuth Passport] Resource parameter mismatch - Auth code: "%s", Token request: "%s"',
						$auth_code_resource,
						$resource
					) );
				}
				throw new \InvalidArgumentException( 'Resource parameter mismatch' );
			}
		}

		// Validate PKCE
		if ( ! PKCEValidator::validate( $auth_code->code_challenge, $code_verifier ) ) {
			throw new \InvalidArgumentException( 'Invalid PKCE verifier' );
		}

		// Generate tokens
		$access_token = $this->token_generator->generateAccessToken();
		$refresh_token = $this->token_generator->generateRefreshToken();

		// Store tokens with resource binding
		$access_success = $this->token_repository->storeAccessToken(
			$access_token,
			$auth_code->client_id,
			(int) $auth_code->user_id,
			$auth_code->scope ?? 'read write',
			$auth_code_resource
		);

		$refresh_success = $this->token_repository->storeRefreshToken(
			$refresh_token,
			$auth_code->client_id,
			(int) $auth_code->user_id,
			$auth_code->scope ?? 'read write',
			$auth_code_resource
		);

		if ( ! $access_success || ! $refresh_success ) {
			throw new \RuntimeException( 'Failed to store tokens' );
		}

		// Delete used authorization code
		$this->token_repository->deleteTokenById( (int) $auth_code->id );

		$response = array(
			'access_token'  => $access_token,
			'refresh_token' => $refresh_token,
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'scope'         => $auth_code->scope ?? 'read write',
		);

		// Include resource in response if present (RFC 8707)
		if ( ! empty( $auth_code_resource ) ) {
			$response['resource'] = $auth_code_resource;
		}

		return $response;
	}

	/**
	 * Validate redirect URI
	 *
	 * @param array  $client Client data
	 * @param string $redirect_uri Redirect URI to validate
	 * @return bool True if valid
	 */
	public function validateRedirectUri( array $client, string $redirect_uri ): bool {
		// For dynamically registered clients
		if ( isset( $client['redirect_uris'] ) && is_array( $client['redirect_uris'] ) ) {
			return in_array( $redirect_uri, $client['redirect_uris'], true );
		}

		// For statically configured clients (backward compatibility)
		return isset( $client['redirect_uri'] ) && $client['redirect_uri'] === $redirect_uri;
	}

	/**
	 * Check if user has already authorized client
	 *
	 * @param int    $user_id User ID
	 * @param string $client_id Client ID
	 * @return bool True if already authorized
	 */
	public function hasUserAuthorizedClient( int $user_id, string $client_id ): bool {
		$authorizations = get_user_meta( $user_id, 'oauth_passport_authorizations', true );
		if ( ! is_array( $authorizations ) ) {
			return false;
		}
		return in_array( $client_id, $authorizations, true );
	}

	/**
	 * Store user authorization for client
	 *
	 * @param int    $user_id User ID
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function storeUserAuthorization( int $user_id, string $client_id ): bool {
		$authorizations = get_user_meta( $user_id, 'oauth_passport_authorizations', true );
		if ( ! is_array( $authorizations ) ) {
			$authorizations = array();
		}
		
		if ( ! in_array( $client_id, $authorizations, true ) ) {
			$authorizations[] = $client_id;
			return (bool) update_user_meta( $user_id, 'oauth_passport_authorizations', $authorizations );
		}
		
		return true;
	}

	/**
	 * Process user consent for authorization
	 *
	 * @param int   $user_id User ID
	 * @param array $params Authorization parameters
	 * @param bool  $granted Whether consent was granted
	 * @return array Authorization response
	 * @throws \Exception If processing fails
	 */
	public function processUserConsent( int $user_id, array $params, bool $granted ): array {
		if ( ! $granted ) {
			throw new \Exception( 'User denied authorization' );
		}

		$client_id = $params['client_id'] ?? '';
		$scope = $params['scope'] ?? 'read';
		$code_challenge = $params['code_challenge'] ?? '';
		$state = $params['state'] ?? '';
		$resource = $params['resource'] ?? '';

		// Generate authorization code with resource parameter
		$auth_code = $this->generateAuthorizationCode( $client_id, $user_id, $code_challenge, $scope, $resource );

		// Store user authorization
		$this->storeUserAuthorization( $user_id, $client_id );

		$response = array(
			'code' => $auth_code,
		);

		if ( ! empty( $state ) ) {
			$response['state'] = $state;
		}

		return $response;
	}

	/**
	 * Validate authorization code
	 *
	 * @param string $code Authorization code
	 * @param string $client_id Client ID
	 * @param string $redirect_uri Redirect URI
	 * @param string $code_verifier PKCE code verifier
	 * @return array|false Authorization code data or false if invalid
	 */
	public function validateAuthorizationCode( string $code, string $client_id, string $redirect_uri, string $code_verifier = '' ) {
		$auth_code = $this->token_repository->getAuthCode( $code );
		if ( ! $auth_code ) {
			return false;
		}

		// Validate client matches
		if ( $auth_code->client_id !== $client_id ) {
			return false;
		}

		// Validate PKCE if provided
		if ( ! empty( $code_verifier ) && ! empty( $auth_code->code_challenge ) ) {
			if ( ! PKCEValidator::validate( $auth_code->code_challenge, $code_verifier ) ) {
				return false;
			}
		}

		return (array) $auth_code;
	}

	/**
	 * Validate authorization request
	 *
	 * @param array $params Request parameters
	 * @return bool|array True if valid, error array if invalid
	 */
	public function validateAuthorizationRequest( array $params ) {
		$required_params = array( 'client_id', 'response_type', 'redirect_uri' );
		
		foreach ( $required_params as $param ) {
			if ( empty( $params[ $param ] ) ) {
				return array(
					'error' => 'invalid_request',
					'error_description' => "Missing required parameter: {$param}",
				);
			}
		}

		// Validate client
		$client = $this->client_repository->getClient( $params['client_id'] );
		if ( ! $client ) {
			return array(
				'error' => 'invalid_client',
				'error_description' => 'Invalid client ID',
			);
		}

		// Validate response type
		if ( $params['response_type'] !== 'code' ) {
			return array(
				'error' => 'unsupported_response_type',
				'error_description' => 'Only "code" response type is supported',
			);
		}

		// Validate redirect URI
		if ( ! $this->validateRedirectUri( $client, $params['redirect_uri'] ) ) {
			return array(
				'error' => 'invalid_redirect_uri',
				'error_description' => 'Invalid redirect URI',
			);
		}

		return true;
	}

	/**
	 * Validate scope
	 *
	 * @param string $scope Requested scope
	 * @param array  $client Client data
	 * @return bool True if valid
	 */
	public function validateScope( string $scope, array $client = array() ): bool {
		return ! empty( $this->scope_manager->validate( $scope ) );
	}

	/**
	 * Format error response
	 *
	 * @param string $error Error code
	 * @param string $description Error description
	 * @param string $state State parameter
	 * @return array Error response
	 */
	public function formatErrorResponse( string $error, string $description, string $state = '' ): array {
		$response = array(
			'error' => $error,
			'error_description' => $description,
		);

		if ( ! empty( $state ) ) {
			$response['state'] = $state;
		}

		return $response;
	}
}
