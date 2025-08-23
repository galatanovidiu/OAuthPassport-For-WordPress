<?php
/**
 * URL Generator Class
 *
 * Handles OAuth URL generation.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

namespace OAuthPassport\Helpers;

/**
 * URL Generator class for handling OAuth URL generation.
 */
class UrlGenerator {

	/**
	 * Get the OAuth authorization URL.
	 *
	 * @param array $params Query parameters for the authorization request.
	 * @return string The authorization URL.
	 */
	public static function get_authorize_url( array $params = array() ): string {
		$defaults = array(
			'response_type' => 'code',
		);
		$params = wp_parse_args( $params, $defaults );

		return add_query_arg( $params, rest_url( 'oauth-passport/v1/authorize' ) );
	}

	/**
	 * Get the OAuth token URL.
	 *
	 * @return string The token endpoint URL.
	 */
	public static function get_token_url(): string {
		return rest_url( 'oauth-passport/v1/token' );
	}

	/**
	 * Get the OAuth client registration URL.
	 *
	 * @return string The registration endpoint URL.
	 */
	public static function get_registration_url(): string {
		return rest_url( 'oauth-passport/v1/register' );
	}
}
