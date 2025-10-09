<?php
/**
 * Client Service
 *
 * Manages OAuth client operations including registration, validation,
 * secret verification, and client management.
 *
 * @package OAuthPassport
 * @subpackage Services
 */

declare( strict_types=1 );

namespace OAuthPassport\Services;

use OAuthPassport\Auth\Schema;
use OAuthPassport\Auth\ScopeManager;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Repositories\TokenRepository;

/**
 * Class ClientService
 *
 * Provides OAuth client management operations including registration,
 * validation, and secret verification.
 */
class ClientService {

	/**
	 * Client repository
	 *
	 * @var ClientRepository
	 */
	private ClientRepository $client_repository;

	/**
	 * Token repository
	 *
	 * @var TokenRepository
	 */
	private TokenRepository $token_repository;

	/**
	 * Client secret manager
	 *
	 * @var ClientSecretManager
	 */
	private ClientSecretManager $secret_manager;

	/**
	 * Secure token generator
	 *
	 * @var SecureTokenGenerator
	 */
	private SecureTokenGenerator $token_generator;

	/**
	 * Scope manager
	 *
	 * @var ScopeManager
	 */
	private ScopeManager $scope_manager;

	/**
	 * Database schema
	 *
	 * @var Schema
	 */
	private Schema $schema;

	/**
	 * Initialize client service
	 *
	 * @param ClientRepository     $client_repository Repository for client data access
	 * @param TokenRepository      $token_repository Repository for token data access
	 * @param ClientSecretManager  $secret_manager Service for secret hashing/verification
	 * @param SecureTokenGenerator $token_generator Service for generating credentials
	 * @param ScopeManager         $scope_manager Service for scope validation
	 * @param Schema               $schema Database schema manager
	 */
	public function __construct(
		ClientRepository $client_repository,
		TokenRepository $token_repository,
		ClientSecretManager $secret_manager,
		SecureTokenGenerator $token_generator,
		ScopeManager $scope_manager,
		Schema $schema
	) {
		$this->client_repository = $client_repository;
		$this->token_repository  = $token_repository;
		$this->secret_manager    = $secret_manager;
		$this->token_generator   = $token_generator;
		$this->scope_manager     = $scope_manager;
		$this->schema            = $schema;
	}

	/**
	 * Register a new OAuth client (RFC 7591)
	 *
	 * @param array $params Client registration parameters
	 * @return array Client registration response
	 * @throws \InvalidArgumentException If validation fails
	 */
	public function registerClient( array $params ): array {
		// Validate required parameters
		if ( empty( $params['client_name'] ) ) {
			throw new \InvalidArgumentException( 'client_name is required' );
		}

		if ( empty( $params['redirect_uris'] ) || ! is_array( $params['redirect_uris'] ) ) {
			throw new \InvalidArgumentException( 'redirect_uris must be a non-empty array' );
		}

		// Validate all redirect URIs
		foreach ( $params['redirect_uris'] as $uri ) {
			// Always allow localhost URLs
			if ( $this->isLocalhostUri( $uri ) ) {
				continue;
			}

			if ( ! wp_http_validate_url( $uri ) ) {
				throw new \InvalidArgumentException( 'Invalid redirect URI: ' . $uri );
			}
		}

		// Generate client credentials
		$client_id     = $this->token_generator->generateClientId();
		$client_secret = $this->token_generator->generateClientSecret();
		$issued_at     = time();

		$hashed_secret = $this->secret_manager->hashClientSecret( $client_secret );

		// Generate registration access token
		$registration_token = $this->token_generator->generateRegistrationToken();

		// Prepare client metadata
		$default_scope = implode( ' ', $this->scope_manager->getDefaultScopes() );

		$client_data = array(
			'client_id'                  => $client_id,
			'client_secret_hash'         => $hashed_secret,
			'client_name'                => sanitize_text_field( $params['client_name'] ),
			'redirect_uris'              => wp_json_encode( $params['redirect_uris'] ),
			'grant_types'                => wp_json_encode( $params['grant_types'] ?? array( 'authorization_code' ) ),
			'response_types'             => wp_json_encode( $params['response_types'] ?? array( 'code' ) ),
			'scope'                      => $params['scope'] ?? $default_scope,
			'allowed_resources'          => wp_json_encode( $params['allowed_resources'] ?? array() ),
			'contacts'                   => wp_json_encode( $params['contacts'] ?? array() ),
			'logo_uri'                   => esc_url_raw( $params['logo_uri'] ?? '' ),
			'client_uri'                 => esc_url_raw( $params['client_uri'] ?? '' ),
			'policy_uri'                 => esc_url_raw( $params['policy_uri'] ?? '' ),
			'tos_uri'                    => esc_url_raw( $params['tos_uri'] ?? '' ),
			'jwks_uri'                   => esc_url_raw( $params['jwks_uri'] ?? '' ),
			'token_endpoint_auth_method' => sanitize_text_field( $params['token_endpoint_auth_method'] ?? 'client_secret_post' ),
			'registration_access_token'  => wp_hash( $registration_token ),
			'registration_client_uri'    => rest_url( 'oauth-passport/v1/register/' . $client_id ),
			'client_id_issued_at'        => $issued_at,
			'client_secret_expires_at'   => 0, // Never expires
		);

		// Store client in database
		$success = $this->client_repository->storeClient( $client_data );

		if ( ! $success ) {
			throw new \RuntimeException( 'Failed to register client' );
		}

		// Store registration token
		$this->storeRegistrationToken( $registration_token, $client_id );

		// Return client information (RFC 7591 compliant response)
		$response = array(
			'client_id'                  => $client_id,
			'client_secret'              => $client_secret,
			'client_id_issued_at'        => $issued_at,
			'client_secret_expires_at'   => 0,
			'registration_access_token'  => $registration_token,
			'registration_client_uri'    => $client_data['registration_client_uri'],
			'client_name'                => $params['client_name'],
			'redirect_uris'              => $params['redirect_uris'],
			'grant_types'                => $params['grant_types'] ?? array( 'authorization_code' ),
			'response_types'             => $params['response_types'] ?? array( 'code' ),
			'scope'                      => $params['scope'] ?? $default_scope,
			'token_endpoint_auth_method' => $params['token_endpoint_auth_method'] ?? 'client_secret_post',
		);

		// Add optional fields if provided
		$optional_fields = array( 'contacts', 'logo_uri', 'client_uri', 'policy_uri', 'tos_uri', 'jwks_uri', 'allowed_resources' );
		foreach ( $optional_fields as $field ) {
			if ( ! empty( $params[ $field ] ) ) {
				$response[ $field ] = $params[ $field ];
			}
		}

		return $response;
	}

	/**
	 * Get client by ID
	 *
	 * @param string $client_id Client ID
	 * @return array|null Client data or null if not found
	 */
	public function getClient( string $client_id ): ?array {
		// First check database for dynamically registered clients
		$db_client = $this->client_repository->getClient( $client_id );

		if ( $db_client ) {
			return array(
				'client_id'          => $db_client['client_id'],
				'client_secret_hash' => $db_client['client_secret_hash'],
				'redirect_uris'      => $db_client['redirect_uris'],
			);
		}

		// Fall back to statically configured clients
		$clients = get_option( 'oauth_passport_clients', array() );
		return $clients[ $client_id ] ?? null;
	}

	/**
	 * Update client configuration
	 *
	 * @param string $client_id Client ID
	 * @param array  $update_data Data to update
	 * @return bool True on success
	 * @throws \InvalidArgumentException If validation fails
	 */
	public function updateClient( string $client_id, array $update_data ): bool {
		// Validate client exists
		$client = $this->getClient( $client_id );
		if ( ! $client ) {
			throw new \InvalidArgumentException( 'Client not found' );
		}

		// Validate redirect URIs if provided
		if ( isset( $update_data['redirect_uris'] ) ) {
			foreach ( $update_data['redirect_uris'] as $uri ) {
				if ( ! $this->isLocalhostUri( $uri ) && ! wp_http_validate_url( $uri ) ) {
					throw new \InvalidArgumentException( 'Invalid redirect URI: ' . $uri );
				}
			}
		}

		return $this->client_repository->updateClient( $client_id, $update_data );
	}

	/**
	 * Delete client and all associated tokens
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function deleteClient( string $client_id ): bool {
		// Delete all tokens for this client first
		$this->token_repository->revokeAllClientTokens( $client_id );

		// Delete client
		return $this->client_repository->deleteClient( $client_id );
	}

	/**
	 * List all clients
	 *
	 * @param int $limit Maximum number of clients to return
	 * @param int $offset Offset for pagination
	 * @return array Array of clients
	 */
	public function listClients( int $limit = 100, int $offset = 0 ): array {
		return $this->client_repository->getAllClients( $limit, $offset );
	}

	/**
	 * Verify client secret
	 *
	 * @param array  $client Client data
	 * @param string $provided_secret Provided secret
	 * @return bool True if secret matches
	 */
	public function verifyClientSecret( array $client, string $provided_secret ): bool {
		// If client has no secret (public client), it can't be verified
		if ( empty( $client['client_secret_hash'] ) ) {
			return false;
		}

		// Use the secure client secret manager for verification
		$verification_result = $this->secret_manager->verifyClientSecret( $provided_secret, $client['client_secret_hash'] );

		// Check if hash needs rehashing and update if needed
		if ( $verification_result && $this->secret_manager->needsRehash( $client['client_secret_hash'] ) ) {
			$new_hash = $this->secret_manager->hashClientSecret( $provided_secret );
			$this->client_repository->rehashClientSecret( $client['client_id'] ?? '', $new_hash );
		}

		return $verification_result;
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
	 * Check if URI is a localhost URL
	 *
	 * @param string $uri URI to check
	 * @return bool True if localhost
	 */
	public function isLocalhostUri( string $uri ): bool {
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

		// Check for *.local domains
		if ( str_ends_with( $host, '.local' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Revoke all tokens for a client
	 *
	 * @param string $client_id Client ID
	 * @return bool True on success
	 */
	public function revokeAllClientTokens( string $client_id ): bool {
		return $this->token_repository->revokeAllClientTokens( $client_id );
	}

	/**
	 * Validate client for manual token generation
	 *
	 * @param string $client_id Client ID
	 * @return bool True if client can receive manual tokens
	 */
	public function validateClientForManualToken( string $client_id ): bool {
		$client = $this->getClient( $client_id );
		return $client !== null;
	}

	/**
	 * Store registration token
	 *
	 * @param string $token Registration token
	 * @param string $client_id Client ID
	 */
	private function storeRegistrationToken( string $token, string $client_id ): void {
		global $wpdb;
		$table = $this->schema->get_table_name();

		$wpdb->insert(
			$table,
			array(
				'token_type'  => 'registration',
				'token_value' => $token,
				'client_id'   => $client_id,
				'user_id'     => 0, // System token
				'expires_at'  => date( 'Y-m-d H:i:s', strtotime( current_time( 'mysql' ) ) + 86400 * 365 ), // 1 year
			)
		);
	}

	/**
	 * Validate registration token
	 *
	 * @param string $token Token value
	 * @param string $client_id Expected client ID
	 * @return bool True if valid
	 */
	public function validateRegistrationToken( string $token, string $client_id ): bool {
		global $wpdb;
		$table = $this->schema->get_table_name();

		// Get all active registration tokens for this client to prevent timing attacks
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.DirectQuery
		$tokens = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT token_value, client_id FROM {$table} 
				WHERE token_type = 'registration' 
				AND client_id = %s
				AND expires_at > %s",
				$client_id,
				current_time( 'mysql' )
			)
		);

		// Use timing-safe comparison to find matching token
		foreach ( $tokens as $stored_token ) {
			if ( \OAuthPassport\Auth\SecurityUtils::validateToken( $token, $stored_token->token_value ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Validate resource parameter against client allowed resources (RFC 8707)
	 *
	 * Checks if a resource URI is allowed for the given client. If the client has no
	 * restrictions set, any valid URI format is allowed. Otherwise, validates against
	 * the client's allowed_resources list.
	 *
	 * @param array  $client Client data
	 * @param string $resource Resource URI to validate
	 * @return bool True if resource is allowed for this client
	 */
	public function validateResource( array $client, string $resource ): bool {
		// Empty resource is always allowed (for backward compatibility)
		if ( empty( $resource ) ) {
			return true;
		}

		// Validate URI format first
		if ( ! $this->isValidResourceUri( $resource ) ) {
			return false;
		}

		// If client has no restrictions, allow any valid URI
		if ( empty( $client['allowed_resources'] ) ) {
			return true;
		}

		// Check if resource is in client's allowed list
		$allowed = $client['allowed_resources'];
		if ( is_string( $allowed ) ) {
			$allowed = json_decode( $allowed, true );
		}

		if ( ! is_array( $allowed ) ) {
			return true; // Malformed allowed_resources, allow by default
		}

		// Normalize both URIs for comparison (lowercase scheme/host, no trailing slash variance)
		$normalized_resource = $this->normalizeResourceUri( $resource );
		foreach ( $allowed as $allowed_uri ) {
			if ( $this->normalizeResourceUri( $allowed_uri ) === $normalized_resource ) {
				return true;
			}
		}

		// Log rejection for debugging
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( sprintf(
				'[OAuth Passport] Resource "%s" not in client\'s allowed list',
				$resource
			) );
		}

		return false;
	}

	/**
	 * Validate resource URI format (RFC 8707)
	 *
	 * Ensures the resource parameter is a valid URI without fragments.
	 * Per RFC 8707, resource MUST be:
	 * - A valid absolute URI
	 * - Must NOT contain a fragment component
	 *
	 * @param string $uri URI to validate
	 * @return bool True if URI format is valid
	 */
	private function isValidResourceUri( string $uri ): bool {
		// Must not contain fragment
		if ( strpos( $uri, '#' ) !== false ) {
			return false;
		}

		$parsed = wp_parse_url( $uri );

		// Must have scheme and host
		if ( empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return false;
		}

		// Scheme must be http or https
		$scheme = strtolower( $parsed['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Normalize resource URI for comparison
	 *
	 * Implements canonical URI format per RFC 8707:
	 * - Lowercase scheme and host
	 * - Consistent trailing slash handling
	 *
	 * @param string $uri URI to normalize
	 * @return string Normalized URI
	 */
	private function normalizeResourceUri( string $uri ): string {
		$parsed = wp_parse_url( $uri );

		if ( ! $parsed || empty( $parsed['scheme'] ) || empty( $parsed['host'] ) ) {
			return $uri; // Return as-is if invalid
		}

		// Lowercase scheme and host
		$scheme = strtolower( $parsed['scheme'] );
		$host = strtolower( $parsed['host'] );

		// Build normalized URI
		$normalized = $scheme . '://' . $host;

		if ( ! empty( $parsed['port'] ) ) {
			// Only include port if it's non-standard
			if ( ( 'https' === $scheme && 443 !== $parsed['port'] ) ||
			     ( 'http' === $scheme && 80 !== $parsed['port'] ) ) {
				$normalized .= ':' . $parsed['port'];
			}
		}

		if ( ! empty( $parsed['path'] ) ) {
			$normalized .= rtrim( $parsed['path'], '/' );
		}

		if ( ! empty( $parsed['query'] ) ) {
			$normalized .= '?' . $parsed['query'];
		}

		return $normalized;
	}
}

