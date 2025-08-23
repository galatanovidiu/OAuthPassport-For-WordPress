<?php
/**
 * Test the new simplified OAuth scope system
 *
 * This file demonstrates how the new scope system works.
 * You can include this in your theme or plugin for testing.
 *
 * @package OAuthPassport\Examples
 */

// Test 1: Check available scopes
add_action( 'init', function() {
	if ( function_exists( 'oauth_passport_get_available_scopes' ) ) {
		$scopes = oauth_passport_get_available_scopes();
		error_log( 'Available OAuth scopes: ' . print_r( $scopes, true ) );
	}
} );

// Test 2: Create a test endpoint to demonstrate scope checking
add_action( 'rest_api_init', function() {
	register_rest_route( 'oauth-test/v1', '/scope-demo', array(
		'methods'             => 'GET',
		'callback'            => 'oauth_test_scope_demo',
		'permission_callback' => function() {
			return oauth_passport_user_can( 'read', 'read' );
		},
	) );
	
	register_rest_route( 'oauth-test/v1', '/write-demo', array(
		'methods'             => 'POST',
		'callback'            => 'oauth_test_write_demo',
		'permission_callback' => function() {
			return oauth_passport_user_can( 'write', 'edit_posts' );
		},
	) );
	
	register_rest_route( 'oauth-test/v1', '/admin-demo', array(
		'methods'             => 'GET',
		'callback'            => 'oauth_test_admin_demo',
		'permission_callback' => function() {
			return oauth_passport_user_can( 'admin', 'manage_options' );
		},
	) );
} );

function oauth_test_scope_demo( WP_REST_Request $request ) {
	$token = oauth_passport_get_current_token();
	
	return array(
		'message' => 'Read access granted',
		'authentication_method' => $token ? 'OAuth' : 'WordPress',
		'user_id' => get_current_user_id(),
		'has_read_scope' => oauth_passport_user_has_scope( 'read' ),
		'has_write_scope' => oauth_passport_user_has_scope( 'write' ),
		'has_admin_scope' => oauth_passport_user_has_scope( 'admin' ),
	);
}

function oauth_test_write_demo( WP_REST_Request $request ) {
	return array(
		'message' => 'Write access granted',
		'user_id' => get_current_user_id(),
		'can_edit_posts' => current_user_can( 'edit_posts' ),
		'can_publish_posts' => current_user_can( 'publish_posts' ),
	);
}

function oauth_test_admin_demo( WP_REST_Request $request ) {
	return array(
		'message' => 'Admin access granted',
		'user_id' => get_current_user_id(),
		'can_manage_options' => current_user_can( 'manage_options' ),
		'can_list_users' => current_user_can( 'list_users' ),
	);
}

// Test 3: Add a shortcode to test scope checking
add_shortcode( 'oauth_scope_test', function( $atts ) {
	$atts = shortcode_atts( array(
		'scope' => 'read',
	), $atts );
	
	$can_access = oauth_passport_user_can( $atts['scope'] );
	
	$output = '<div class="oauth-scope-test">';
	$output .= '<h3>OAuth Scope Test: ' . esc_html( $atts['scope'] ) . '</h3>';
	$output .= '<p>Access granted: ' . ( $can_access ? 'Yes' : 'No' ) . '</p>';
	
	$token = oauth_passport_get_current_token();
	if ( $token ) {
		$output .= '<p>Authentication: OAuth</p>';
		$output .= '<p>Token scopes: ' . esc_html( $token->scope ) . '</p>';
	} else {
		$output .= '<p>Authentication: WordPress</p>';
		$output .= '<p>User capabilities: ' . esc_html( implode( ', ', wp_get_current_user()->allcaps ) ) . '</p>';
	}
	
	$output .= '</div>';
	
	return $output;
} );
