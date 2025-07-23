<?php
/**
 * OAuth Passport Integration Example
 *
 * This file demonstrates how to integrate OAuth Passport with your WordPress plugin or theme.
 *
 * @package OAuthPassport\Examples
 */

// Example 1: Protecting a custom REST API endpoint.
add_action( 'rest_api_init', function() {
	register_rest_route( 'myplugin/v1', '/protected-data', array(
		'methods'             => 'GET',
		'callback'            => 'myplugin_get_protected_data',
		'permission_callback' => 'is_user_logged_in', // OAuth Passport will authenticate.
	) );
} );

function myplugin_get_protected_data( WP_REST_Request $request ) {
	// Get information about the OAuth token.
	$token = oauth_passport_get_current_token();
	
	if ( $token ) {
		// This is an OAuth authenticated request.
		return array(
			'message'    => 'Authenticated via OAuth',
			'client_id'  => $token->client_id,
			'user_id'    => $token->user_id,
			'scopes'     => explode( ' ', $token->scope ),
		);
	} else {
		// This might be authenticated via cookies or another method.
		return array(
			'message' => 'Authenticated via WordPress session',
			'user_id' => get_current_user_id(),
		);
	}
}

// Example 2: Requiring specific OAuth scopes.
add_action( 'rest_api_init', function() {
	register_rest_route( 'myplugin/v1', '/admin-only', array(
		'methods'             => 'POST',
		'callback'            => 'myplugin_admin_action',
		'permission_callback' => 'myplugin_check_admin_scope',
	) );
} );

function myplugin_check_admin_scope() {
	// First check if user is logged in.
	if ( ! is_user_logged_in() ) {
		return false;
	}
	
	// If OAuth authenticated, check for admin scope.
	if ( oauth_passport_get_current_token() ) {
		return oauth_passport_user_has_scope( 'admin' );
	}
	
	// For non-OAuth requests, check WordPress capabilities.
	return current_user_can( 'manage_options' );
}

function myplugin_admin_action( WP_REST_Request $request ) {
	return array(
		'success' => true,
		'message' => 'Admin action completed',
	);
}

// Example 3: Adding custom OAuth scopes.
add_filter( 'oauth_passport_scopes', function( $scopes ) {
	// Add custom scopes for your plugin.
	$scopes['posts:publish']     = __( 'Publish posts', 'myplugin' );
	$scopes['posts:delete']      = __( 'Delete posts', 'myplugin' );
	$scopes['media:upload']      = __( 'Upload media files', 'myplugin' );
	$scopes['settings:read']     = __( 'Read plugin settings', 'myplugin' );
	$scopes['settings:write']    = __( 'Modify plugin settings', 'myplugin' );
	
	return $scopes;
} );

// Example 4: Enforcing custom scopes in your endpoints.
add_action( 'rest_api_init', function() {
	register_rest_route( 'myplugin/v1', '/publish-post', array(
		'methods'             => 'POST',
		'callback'            => 'myplugin_publish_post',
		'permission_callback' => function() {
			// Check if user can publish posts.
			if ( ! is_user_logged_in() ) {
				return new WP_Error( 'not_logged_in', 'Authentication required', array( 'status' => 401 ) );
			}
			
			// For OAuth requests, check scope.
			if ( oauth_passport_get_current_token() ) {
				if ( ! oauth_passport_user_has_scope( 'posts:publish' ) ) {
					return new WP_Error( 'insufficient_scope', 'Required scope: posts:publish', array( 'status' => 403 ) );
				}
			}
			
			// Also check WordPress capability.
			return current_user_can( 'publish_posts' );
		},
	) );
} );

// Example 5: Programmatically registering an OAuth client.
add_action( 'init', function() {
	// Only run this once, perhaps on plugin activation.
	if ( ! oauth_passport_get_client( 'my_custom_app' ) ) {
		oauth_passport_register_client(
			'my_custom_app',
			'super_secret_key_here',
			'https://myapp.com/oauth/callback',
			array(
				'client_name' => 'My Custom Application',
				'scope'       => 'read write posts:publish',
			)
		);
	}
} );

// Example 6: Creating an OAuth login button.
add_shortcode( 'oauth_login', function( $atts ) {
	$atts = shortcode_atts( array(
		'client_id'    => '',
		'redirect_uri' => '',
		'scope'        => 'read',
		'button_text'  => __( 'Login with OAuth', 'myplugin' ),
	), $atts );
	
	if ( empty( $atts['client_id'] ) || empty( $atts['redirect_uri'] ) ) {
		return '<p>' . __( 'OAuth client_id and redirect_uri are required.', 'myplugin' ) . '</p>';
	}
	
	// Generate PKCE challenge.
	$verifier = wp_generate_password( 128, false );
	$challenge = base64_encode( hash( 'sha256', $verifier, true ) );
	$challenge = rtrim( strtr( $challenge, '+/', '-_' ), '=' );
	
	// Store verifier in session or pass to your app.
	set_transient( 'oauth_verifier_' . get_current_user_id(), $verifier, 600 );
	
	$auth_url = oauth_passport_get_authorize_url( array(
		'client_id'             => $atts['client_id'],
		'redirect_uri'          => $atts['redirect_uri'],
		'scope'                 => $atts['scope'],
		'state'                 => wp_create_nonce( 'oauth_login' ),
		'code_challenge'        => $challenge,
		'code_challenge_method' => 'S256',
	) );
	
	return sprintf(
		'<a href="%s" class="button oauth-login-button">%s</a>',
		esc_url( $auth_url ),
		esc_html( $atts['button_text'] )
	);
} );

// Example 7: Handling OAuth callback in your application.
add_action( 'init', function() {
	if ( isset( $_GET['oauth_callback'] ) && isset( $_GET['code'] ) ) {
		// Get the stored verifier.
		$verifier = get_transient( 'oauth_verifier_' . get_current_user_id() );
		if ( ! $verifier ) {
			wp_die( 'Invalid OAuth session' );
		}
		
		// Exchange code for token.
		$response = wp_remote_post( oauth_passport_get_token_url(), array(
			'body' => array(
				'grant_type'    => 'authorization_code',
				'code'          => sanitize_text_field( wp_unslash( $_GET['code'] ) ),
				'client_id'     => 'your_client_id',
				'client_secret' => 'your_client_secret',
				'code_verifier' => $verifier,
			),
		) );
		
		if ( ! is_wp_error( $response ) ) {
			$token_data = json_decode( wp_remote_retrieve_body( $response ), true );
			// Store tokens securely and use them for API calls.
			update_user_meta( get_current_user_id(), 'oauth_tokens', $token_data );
		}
		
		// Clean up.
		delete_transient( 'oauth_verifier_' . get_current_user_id() );
	}
} );

// Example 8: Making authenticated API calls with OAuth tokens.
function myplugin_call_api_with_oauth( $endpoint, $token ) {
	$response = wp_remote_get( $endpoint, array(
		'headers' => array(
			'Authorization' => 'Bearer ' . $token,
		),
	) );
	
	if ( is_wp_error( $response ) ) {
		return $response;
	}
	
	return json_decode( wp_remote_retrieve_body( $response ), true );
}

// Example 9: Refreshing expired tokens.
function myplugin_refresh_oauth_token( $refresh_token, $client_id, $client_secret ) {
	$response = wp_remote_post( oauth_passport_get_token_url(), array(
		'body' => array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refresh_token,
			'client_id'     => $client_id,
			'client_secret' => $client_secret,
		),
	) );
	
	if ( is_wp_error( $response ) ) {
		return $response;
	}
	
	return json_decode( wp_remote_retrieve_body( $response ), true );
}

// Example 10: Conditionally loading features based on OAuth availability.
add_action( 'plugins_loaded', function() {
	if ( ! function_exists( 'oauth_passport_is_enabled' ) || ! oauth_passport_is_enabled() ) {
		// OAuth Passport is not available or disabled.
		// Fall back to alternative authentication method.
		return;
	}
	
	// OAuth Passport is available, register OAuth-specific features.
	add_action( 'rest_api_init', function() {
		// Register OAuth-protected endpoints.
	} );
} ); 