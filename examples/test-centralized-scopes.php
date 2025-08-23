<?php
/**
 * Test the centralized OAuth scope system
 *
 * This file demonstrates how the centralized scope system works.
 * All scope definitions now come from a single source of truth.
 *
 * @package OAuthPassport\Examples
 */

// Test 1: Verify centralized scope definitions
add_action( 'init', function() {
	if ( function_exists( 'oauth_passport_get_available_scopes' ) ) {
		$scopes = oauth_passport_get_available_scopes();
		$scope_names = oauth_passport_get_scope_names();
		$default_scopes = oauth_passport_get_default_scopes();
		
		error_log( '=== CENTRALIZED SCOPE TEST ===' );
		error_log( 'Available scopes: ' . print_r( $scopes, true ) );
		error_log( 'Scope names: ' . print_r( $scope_names, true ) );
		error_log( 'Default scopes: ' . print_r( $default_scopes, true ) );
		
		// Verify consistency
		$direct_scopes = \OAuthPassport\Auth\ScopeManager::get_scopes();
		$direct_names = array_keys( $direct_scopes );
		$direct_defaults = \OAuthPassport\Auth\ScopeManager::get_default_scopes();
		
		error_log( 'Direct from ScopeManager: ' . print_r( $direct_scopes, true ) );
		error_log( 'Consistency check - Names match: ' . ( $scope_names === $direct_names ? 'YES' : 'NO' ) );
		error_log( 'Consistency check - Defaults match: ' . ( $default_scopes === $direct_defaults ? 'YES' : 'NO' ) );
	}
} );

// Test 2: Create endpoints that use centralized scopes
add_action( 'rest_api_init', function() {
	// Test endpoint that shows all available scopes
	register_rest_route( 'oauth-centralized/v1', '/scopes', array(
		'methods'             => 'GET',
		'callback'            => 'oauth_test_centralized_scopes',
		'permission_callback' => function() {
			return oauth_passport_user_can( 'read', 'read' );
		},
	) );
	
	// Test endpoint for each scope
	$scopes = oauth_passport_get_scope_names();
	foreach ( $scopes as $scope ) {
		register_rest_route( 'oauth-centralized/v1', '/' . $scope, array(
			'methods'             => 'GET',
			'callback'            => 'oauth_test_scope_endpoint',
			'permission_callback' => function() use ( $scope ) {
				return oauth_passport_user_can( $scope );
			},
		) );
	}
} );

function oauth_test_centralized_scopes( WP_REST_Request $request ) {
	return array(
		'message' => 'Centralized scope system test',
		'available_scopes' => oauth_passport_get_available_scopes(),
		'scope_names' => oauth_passport_get_scope_names(),
		'default_scopes' => oauth_passport_get_default_scopes(),
		'constants' => array(
			'AVAILABLE_SCOPES' => \OAuthPassport\Auth\ScopeManager::AVAILABLE_SCOPES,
			'DEFAULT_SCOPES' => \OAuthPassport\Auth\ScopeManager::DEFAULT_SCOPES,
		),
	);
}

function oauth_test_scope_endpoint( WP_REST_Request $request ) {
	$scope = basename( $request->get_route() );
	
	return array(
		'message' => "Access granted for scope: {$scope}",
		'scope' => $scope,
		'user_id' => get_current_user_id(),
		'authentication_method' => oauth_passport_get_current_token() ? 'OAuth' : 'WordPress',
	);
}

// Test 3: Shortcode to display centralized scope information
add_shortcode( 'oauth_centralized_test', function( $atts ) {
	$output = '<div class="oauth-centralized-test">';
	$output .= '<h3>Centralized OAuth Scope System</h3>';
	
	$output .= '<h4>Available Scopes:</h4>';
	$scopes = oauth_passport_get_available_scopes();
	$output .= '<ul>';
	foreach ( $scopes as $scope => $description ) {
		$output .= '<li><strong>' . esc_html( $scope ) . '</strong>: ' . esc_html( $description ) . '</li>';
	}
	$output .= '</ul>';
	
	$output .= '<h4>Default Scopes:</h4>';
	$defaults = oauth_passport_get_default_scopes();
	$output .= '<p>' . esc_html( implode( ', ', $defaults ) ) . '</p>';
	
	$output .= '<h4>Current User Access:</h4>';
	foreach ( array_keys( $scopes ) as $scope ) {
		$can_access = oauth_passport_user_can( $scope );
		$output .= '<p><strong>' . esc_html( $scope ) . '</strong>: ' . ( $can_access ? 'Yes' : 'No' ) . '</p>';
	}
	
	$output .= '</div>';
	
	return $output;
} );
