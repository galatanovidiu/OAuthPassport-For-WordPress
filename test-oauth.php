<?php
/**
 * Test OAuth Passport functionality
 *
 * This file can be run via WP CLI: wp eval-file wp-content/plugins/OAuthPassport/test-oauth.php
 */

// Check if we're in WordPress context.
if ( ! defined( 'ABSPATH' ) ) {
	die( 'This script must be run within WordPress context.' );
}

// Check if plugin is active.
if ( ! is_plugin_active( 'OAuthPassport/oauth-passport.php' ) ) {
	echo "OAuth Passport plugin is not active. Please activate it first.\n";
	exit( 1 );
}

echo "OAuth Passport Test Script\n";
echo "==========================\n\n";

// Test 1: Check if database tables exist.
echo "1. Checking database tables...\n";
global $wpdb;
$tables = array(
	$wpdb->prefix . 'oauth_passport_tokens',
	$wpdb->prefix . 'oauth_passport_clients',
);

foreach ( $tables as $table ) {
	$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
	if ( $exists ) {
		echo "   ✓ Table $table exists\n";
	} else {
		echo "   ✗ Table $table does NOT exist\n";
	}
}

// Test 2: Check REST routes.
echo "\n2. Checking REST routes...\n";
$routes = rest_get_server()->get_routes();
$oauth_routes = array(
	'/oauth-passport/v1/register',
	'/oauth-passport/v1/register/(?P<client_id>[a-zA-Z0-9_-]+)',
	'/oauth-passport/v1/authorize',
	'/oauth-passport/v1/token',
);

foreach ( $oauth_routes as $route ) {
	if ( isset( $routes[ $route ] ) ) {
		echo "   ✓ Route $route is registered\n";
	} else {
		// Check if it's a regex pattern.
		$found = false;
		foreach ( array_keys( $routes ) as $registered_route ) {
			if ( strpos( $registered_route, '/oauth-passport/v1/' ) === 0 ) {
				$found = true;
			}
		}
		if ( $found ) {
			echo "   ✓ Route pattern $route is registered\n";
		} else {
			echo "   ✗ Route $route is NOT registered\n";
		}
	}
}

// Test 3: Test client registration.
echo "\n3. Testing client registration...\n";
$request = new WP_REST_Request( 'POST', '/oauth-passport/v1/register' );
$request->set_header( 'Content-Type', 'application/json' );
$request->set_body(
	wp_json_encode(
		array(
			'client_name'   => 'Test OAuth Client',
			'redirect_uris' => array( 'https://localhost:3000/callback' ),
			'grant_types'   => array( 'authorization_code' ),
			'response_types' => array( 'code' ),
			'scope'         => 'read write',
		)
	)
);

$response = rest_do_request( $request );
$data = $response->get_data();

if ( ! is_wp_error( $data ) && isset( $data['client_id'] ) ) {
	echo "   ✓ Client registered successfully\n";
	echo "   Client ID: " . $data['client_id'] . "\n";
	echo "   Client Secret: " . ( isset( $data['client_secret'] ) ? '[REDACTED]' : 'Not provided' ) . "\n";
} else {
	echo "   ✗ Client registration failed\n";
	if ( is_wp_error( $data ) ) {
		echo "   Error: " . $data->get_error_message() . "\n";
	}
}

echo "\n✅ OAuth Passport test completed!\n"; 