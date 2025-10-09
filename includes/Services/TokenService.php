<?php
/**
 * Token Service
 *
 * Manages OAuth token operations including validation, refresh, revocation,
 * and cleanup of expired tokens with secure client authentication.
 *
 * @package OAuthPassport
 * @subpackage Services
 */

declare( strict_types=1 );

namespace OAuthPassport\Services;

use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Auth\ClientSecretManager;

/**
 * Class TokenService
 *
 * Provides OAuth token management including validation, refresh,
 * revocation, and automatic cleanup with secure client verification.
 */
class TokenService {

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
	 * Client secret manager
	 *
	 * @var ClientSecretManager
	 */
	private ClientSecretManager $secret_manager;

	/**
	 * Initialize token service
	 *
     * @param SecureTokenGenerator $token_generator Service for generating new tokens
     * @param TokenRepository      $token_repository Repository for token storage and retrieval
     * @param ClientRepository     $client_repository Repository for client validation
     * @param ClientSecretManager  $secret_manager Service for client secret verification
     */
    public function __construct(
        SecureTokenGenerator $token_generator,
        TokenRepository $token_repository,
        ClientRepository $client_repository,
        ClientSecretManager $secret_manager
    ) {
        $this->token_generator = $token_generator;
        $this->token_repository = $token_repository;
        $this->client_repository = $client_repository;
        $this->secret_manager = $secret_manager;
	}

    /**
     * Validate access token
     *
     * Validates an OAuth access token and returns associated data
     * if the token is valid and not expired.
     *
     * @param string $token Access token to validate
     * @return object|null Token data or null if invalid/expired
     */
    public function validateAccessToken( string $token ): ?object {
        return $this->token_repository->validateAccessToken( $token );
    }

    /**
     * Issue new token pair for a client and user.
     *
     * @param string $client_id Client identifier.
     * @param int    $user_id   WordPress user ID.
     * @param string $scope     Space separated scope string.
     * @param string $resource  Target resource URI (RFC 8707).
     *
     * @return array<string, string|int> Token payload suitable for API responses.
     */
    public function issueTokens( string $client_id, int $user_id, string $scope = 'read', string $resource = '' ): array {
        $client = $this->client_repository->getClient( $client_id );
        if ( ! $client ) {
            throw new \InvalidArgumentException( 'Unknown client.' );
        }

        $normalized_scope = trim( $scope ) !== '' ? $scope : 'read';

        $access_token  = $this->token_generator->generateAccessToken();
        $refresh_token = $this->token_generator->generateRefreshToken();

        $this->token_repository->storeAccessToken( $access_token, $client_id, $user_id, $normalized_scope, $resource );
        $this->token_repository->storeRefreshToken( $refresh_token, $client_id, $user_id, $normalized_scope, $resource );

        $response = array(
            'access_token'  => $access_token,
            'refresh_token' => $refresh_token,
            'token_type'    => 'Bearer',
            'expires_in'    => 3600,
            'scope'         => $normalized_scope,
        );

        // Include resource in response if present (RFC 8707)
        if ( ! empty( $resource ) ) {
            $response['resource'] = $resource;
        }

        return $response;
    }

	/**
	 * Refresh access token
	 *
	 * Exchanges a valid refresh token for new access and refresh tokens.
	 * Validates client credentials and implements token rotation for security.
	 *
	 * @param string $refresh_token Refresh token to exchange
	 * @param string $client_id Client ID requesting refresh
	 * @param string $client_secret Client secret (optional for public clients)
	 * @return array New token data with access_token and refresh_token
	 * @throws \Exception If refresh fails or tokens are invalid
	 */
	public function refreshAccessToken( string $refresh_token, string $client_id, string $client_secret = '' ): array {
		// Get refresh token
		$token_data = $this->token_repository->getRefreshToken( $refresh_token );
		if ( ! $token_data ) {
			throw new \InvalidArgumentException( 'Invalid or expired refresh token' );
		}

		// Validate client
		$client = $this->client_repository->getClient( $client_id );
		if ( ! $client || $client['client_id'] !== $token_data->client_id ) {
			throw new \InvalidArgumentException( 'Invalid client for this refresh token' );
		}

		// Verify client secret if provided
		if ( ! empty( $client_secret ) && ! $this->verifyClientSecret( $client, $client_secret ) ) {
			throw new \InvalidArgumentException( 'Invalid client credentials' );
		}

		// Generate new tokens
		$new_access_token = $this->token_generator->generateAccessToken();
		$new_refresh_token = $this->token_generator->generateRefreshToken();

		// Preserve resource binding from refresh token (RFC 8707)
		$resource = $token_data->resource ?? '';

		// Store new tokens with preserved resource binding
		$access_success = $this->token_repository->storeAccessToken(
			$new_access_token,
			$token_data->client_id,
			(int) $token_data->user_id,
			$token_data->scope ?? 'read write',
			$resource
		);

		$refresh_success = $this->token_repository->storeRefreshToken(
			$new_refresh_token,
			$token_data->client_id,
			(int) $token_data->user_id,
			$token_data->scope ?? 'read write',
			$resource
		);

		if ( ! $access_success || ! $refresh_success ) {
			throw new \RuntimeException( 'Failed to store new tokens' );
		}

		// Delete old refresh token (token rotation)
		$this->token_repository->deleteTokenById( (int) $token_data->id );

		$response = array(
			'access_token'  => $new_access_token,
			'refresh_token' => $new_refresh_token,
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'scope'         => $token_data->scope ?? 'read write',
		);

		// Include resource in response if present (RFC 8707)
		if ( ! empty( $resource ) ) {
			$response['resource'] = $resource;
		}

		return $response;
	}

	/**
	 * Revoke token
	 *
	 * @param string $token Token to revoke
	 * @return bool True on success
	 */
	public function revokeToken( string $token ): bool {
		return $this->token_repository->deleteToken( $token );
	}

	/**
	 * Clean up expired tokens
	 *
	 * @return int Number of deleted tokens
	 */
	public function cleanupExpiredTokens(): int {
		return $this->token_repository->cleanupExpiredTokens();
	}

	/**
	 * Verify client secret
	 *
	 * @param array  $client Client data
	 * @param string $provided_secret Provided secret
	 * @return bool True if valid
	 */
	private function verifyClientSecret( array $client, string $provided_secret ): bool {
		// If client has no secret (public client), it can't be verified against a provided secret
		if ( empty( $client['client_secret_hash'] ) ) {
			return false;
		}

		// Use the secure client secret manager for verification
		$verification_result = $this->secret_manager->verifyClientSecret( $provided_secret, $client['client_secret_hash'] );

		// Check if hash needs rehashing and update if needed
		if ( $verification_result && $this->secret_manager->needsRehash( $client['client_secret_hash'] ) ) {
			$this->rehashClientSecret( $client['client_id'] ?? '', $provided_secret );
		}

		return $verification_result;
	}

	/**
	 * Rehash client secret with new secure algorithm
	 *
	 * @param string $client_id Client ID
	 * @param string $plain_secret Plain text secret
	 */
	private function rehashClientSecret( string $client_id, string $plain_secret ): void {
		if ( empty( $client_id ) ) {
			return;
		}

		try {
			$new_hash = $this->secret_manager->hashClientSecret( $plain_secret );
			
			$this->client_repository->updateClient(
				$client_id,
				array( 
					'client_secret_hash' => $new_hash,
					'secret_version' => '2.0',
				)
			);
		} catch ( \Exception $e ) {
			// Log error but don't fail the authentication
			error_log( 'OAuth Passport: Failed to rehash client secret: ' . $e->getMessage() );
		}
	}
}
