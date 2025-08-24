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

use OAuthPassport\Contracts\TokenGeneratorInterface;
use OAuthPassport\Contracts\TokenRepositoryInterface;
use OAuthPassport\Contracts\ClientRepositoryInterface;
use OAuthPassport\Contracts\ScopeValidatorInterface;
use OAuthPassport\Auth\PKCEValidator;

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
	 * @var TokenGeneratorInterface
	 */
	private TokenGeneratorInterface $token_generator;

	/**
	 * Token repository
	 *
	 * @var TokenRepositoryInterface
	 */
	private TokenRepositoryInterface $token_repository;

	/**
	 * Client repository
	 *
	 * @var ClientRepositoryInterface
	 */
	private ClientRepositoryInterface $client_repository;

	/**
	 * Scope validator
	 *
	 * @var ScopeValidatorInterface
	 */
	private ScopeValidatorInterface $scope_validator;

	/**
	 * Initialize authorization service
	 *
	 * @param TokenGeneratorInterface  $token_generator Service for generating authorization codes
	 * @param TokenRepositoryInterface $token_repository Repository for token storage and retrieval
	 * @param ClientRepositoryInterface $client_repository Repository for client validation
	 * @param ScopeValidatorInterface  $scope_validator Service for scope validation and filtering
	 */
	public function __construct(
		TokenGeneratorInterface $token_generator,
		TokenRepositoryInterface $token_repository,
		ClientRepositoryInterface $client_repository,
		ScopeValidatorInterface $scope_validator
	) {
		$this->token_generator = $token_generator;
		$this->token_repository = $token_repository;
		$this->client_repository = $client_repository;
		$this->scope_validator = $scope_validator;
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
	 * @return string Generated authorization code
	 * @throws \Exception If generation fails or client is invalid
	 */
	public function generateAuthorizationCode( string $client_id, int $user_id, string $code_challenge, string $scope ): string {
		// Validate client exists
		$client = $this->client_repository->getClient( $client_id );
		if ( ! $client ) {
			throw new \InvalidArgumentException( 'Invalid client ID' );
		}

		// Validate and filter scopes
		$valid_scopes = $this->scope_validator->validateScopes( $scope );
		$filtered_scopes = $this->scope_validator->filterScopesByUserCapabilities( $valid_scopes, $user_id );
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
	 * @return array Token data
	 * @throws \Exception If validation fails
	 */
	public function exchangeAuthorizationCode( string $code, string $client_id, string $code_verifier ): array {
		// Get authorization code
		$auth_code = $this->token_repository->getAuthCode( $code );
		if ( ! $auth_code ) {
			throw new \InvalidArgumentException( 'Invalid or expired authorization code' );
		}

		// Validate client matches
		if ( $auth_code->client_id !== $client_id ) {
			throw new \InvalidArgumentException( 'Client ID mismatch' );
		}

		// Validate PKCE
		if ( ! PKCEValidator::validate( $auth_code->code_challenge, $code_verifier ) ) {
			throw new \InvalidArgumentException( 'Invalid PKCE verifier' );
		}

		// Generate tokens
		$access_token = $this->token_generator->generateAccessToken();
		$refresh_token = $this->token_generator->generateRefreshToken();

		// Store tokens
		$access_success = $this->token_repository->storeAccessToken(
			$access_token,
			$auth_code->client_id,
			(int) $auth_code->user_id,
			$auth_code->scope ?? 'read write'
		);

		$refresh_success = $this->token_repository->storeRefreshToken(
			$refresh_token,
			$auth_code->client_id,
			(int) $auth_code->user_id,
			$auth_code->scope ?? 'read write'
		);

		if ( ! $access_success || ! $refresh_success ) {
			throw new \RuntimeException( 'Failed to store tokens' );
		}

		// Delete used authorization code
		$this->token_repository->deleteTokenById( (int) $auth_code->id );

		return array(
			'access_token'  => $access_token,
			'refresh_token' => $refresh_token,
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'scope'         => $auth_code->scope ?? 'read write',
		);
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

		// Generate authorization code
		$auth_code = $this->generateAuthorizationCode( $client_id, $user_id, $code_challenge, $scope );

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
		return $this->scope_validator->validateScopes( $scope ) !== false;
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
