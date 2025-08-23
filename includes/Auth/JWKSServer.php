<?php
/**
 * JWKS (JSON Web Key Set) Server for OAuth Passport
 *
 * Provides public key discovery for JWT signature verification.
 *
 * @package OAuthPassport
 * @subpackage Auth
 */

declare( strict_types=1 );

namespace OAuthPassport\Auth;

/**
 * Class JWKSServer
 *
 * Handles JWKS endpoint for public key discovery.
 */
class JWKSServer {
	/**
	 * Option name for storing keys
	 *
	 * @var string
	 */
	private const KEYS_OPTION = 'oauth_passport_jwks_keys';

	/**
	 * Initialize JWKS server
	 */
	public function __construct() {
		// Register REST route.
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );

		// Initialize keys if not exists.
		add_action( 'init', array( $this, 'maybe_initialize_keys' ) );
	}

	/**
	 * Register JWKS endpoint
	 */
	public function register_routes(): void {
		register_rest_route(
			'oauth-passport/v1',
			'/jwks',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'handle_jwks_request' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Initialize RSA key pair if not exists
	 */
	public function maybe_initialize_keys(): void {
		$keys = get_option( self::KEYS_OPTION, array() );

		if ( empty( $keys ) ) {
			$this->generate_key_pair();
		}
	}

	/**
	 * Handle JWKS request
	 *
	 * @param \WP_REST_Request $request The request object.
	 *
	 * @return \WP_REST_Response
	 */
	public function handle_jwks_request( \WP_REST_Request $request ): \WP_REST_Response {
		$keys = get_option( self::KEYS_OPTION, array() );

		if ( empty( $keys ) ) {
			$keys = $this->generate_key_pair();
		}

		// Build JWK Set response.
		$jwks = array(
			'keys' => array(),
		);

		foreach ( $keys as $kid => $key_data ) {
			// Only include public keys in JWKS.
			if ( isset( $key_data['public_key'] ) ) {
				$public_key = openssl_pkey_get_public( $key_data['public_key'] );
				if ( $public_key ) {
					$details = openssl_pkey_get_details( $public_key );
					if ( $details && isset( $details['rsa'] ) ) {
						$jwks['keys'][] = array(
							'kty' => 'RSA',
							'kid' => $kid,
							'use' => 'sig',
							'alg' => 'RS256',
							'n'   => $this->base64url_encode( $details['rsa']['n'] ),
							'e'   => $this->base64url_encode( $details['rsa']['e'] ),
						);
					}
				}
			}
		}

		// Set cache headers.
		$response = rest_ensure_response( $jwks );
		$response->header( 'Cache-Control', 'public, max-age=86400' ); // Cache for 24 hours.

		return $response;
	}

	/**
	 * Generate RSA key pair
	 *
	 * @return array Generated keys.
	 */
	private function generate_key_pair(): array {
		// Configure key generation.
		$config = array(
			'private_key_bits' => 2048,
			'private_key_type' => OPENSSL_KEYTYPE_RSA,
		);

		// Generate new key pair.
		$res = openssl_pkey_new( $config );
		if ( ! $res ) {
			return array();
		}

		// Extract private key.
		$private_key = '';
		openssl_pkey_export( $res, $private_key );

		// Extract public key.
		$public_key_details = openssl_pkey_get_details( $res );
		$public_key         = $public_key_details['key'] ?? '';

		// Generate key ID.
		$kid = 'key-' . wp_generate_password( 16, false );

		// Store keys.
		$keys = array(
			$kid => array(
				'kid'         => $kid,
				'private_key' => $private_key,
				'public_key'  => $public_key,
				'created_at'  => time(),
				'status'      => 'active',
			),
		);

		update_option( self::KEYS_OPTION, $keys );

		return $keys;
	}

	/**
	 * Get active signing key
	 *
	 * @return array|null Active key data or null if not found.
	 */
	public function get_active_signing_key(): ?array {
		$keys = get_option( self::KEYS_OPTION, array() );

		// Find active key.
		foreach ( $keys as $key_data ) {
			if ( 'active' === ( $key_data['status'] ?? '' ) ) {
				return $key_data;
			}
		}

		// If no active key, generate new one.
		$new_keys = $this->generate_key_pair();
		return reset( $new_keys );
	}

	/**
	 * Rotate keys
	 *
	 * Generates new key pair and marks old keys as inactive.
	 */
	public function rotate_keys(): void {
		$keys = get_option( self::KEYS_OPTION, array() );

		// Mark all existing keys as inactive.
		foreach ( $keys as &$key_data ) {
			$key_data['status']      = 'inactive';
			$key_data['inactive_at'] = time();
		}

		// Generate new key pair.
		$new_key_pair = $this->generate_key_pair();

		// Merge with existing keys.
		$keys = array_merge( $keys, $new_key_pair );

		// Keep only last 5 keys.
		if ( count( $keys ) > 5 ) {
			$keys = array_slice( $keys, -5, 5, true );
		}

		update_option( self::KEYS_OPTION, $keys );
	}

	/**
	 * Base64url encode
	 *
	 * @param string $data Data to encode.
	 * @return string Base64url encoded string.
	 */
	private function base64url_encode( string $data ): string {
		return rtrim( strtr( base64_encode( $data ), '+/', '-_' ), '=' );
	}

	/**
	 * Sign data with active key
	 *
	 * @param string $data Data to sign.
	 * @return array|null Signature data with kid or null on failure.
	 */
	public function sign_data( string $data ): ?array {
		$active_key = $this->get_active_signing_key();
		if ( ! $active_key || ! isset( $active_key['private_key'] ) ) {
			return null;
		}

		$signature  = '';
		$private_key = openssl_pkey_get_private( $active_key['private_key'] );

		if ( ! $private_key ) {
			return null;
		}

		$success = openssl_sign( $data, $signature, $private_key, OPENSSL_ALGO_SHA256 );

		if ( ! $success ) {
			return null;
		}

		return array(
			'signature' => base64_encode( $signature ),
			'kid'       => $active_key['kid'],
		);
	}

	/**
	 * Verify signature with public key
	 *
	 * @param string $data Data that was signed.
	 * @param string $signature Signature to verify.
	 * @param string $kid Key ID used for signing.
	 * @return bool True if signature is valid.
	 */
	public function verify_signature( string $data, string $signature, string $kid ): bool {
		$keys = get_option( self::KEYS_OPTION, array() );

		if ( ! isset( $keys[ $kid ] ) || ! isset( $keys[ $kid ]['public_key'] ) ) {
			return false;
		}

		$public_key = openssl_pkey_get_public( $keys[ $kid ]['public_key'] );
		if ( ! $public_key ) {
			return false;
		}

		return openssl_verify( $data, base64_decode( $signature ), $public_key, OPENSSL_ALGO_SHA256 ) === 1;
	}
} 
