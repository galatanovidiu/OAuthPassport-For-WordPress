<?php
/**
 * OAuth Passport Usage Examples
 *
 * Demonstrates the clean OOP API for OAuth Passport functionality.
 * No global functions needed - everything is discoverable through the main API.
 *
 * @package OAuthPassport
 */

declare( strict_types=1 );

use OAuthPassport\OAuthPassport;

/**
 * Example 1: Authentication Context
 * 
 * Handle authentication and authorization for the current request.
 */
function example_authentication() {
	$auth = OAuthPassport::auth();
	
	// Check if request is OAuth authenticated
	if ( $auth->isOAuthAuthenticated() ) {
		$token = $auth->getCurrentToken();
		echo "OAuth authenticated as user {$token->user_id} from client {$token->client_id}";
		
		// Check specific scope
		if ( $auth->hasScope( 'write' ) ) {
			echo "User has write access";
		}
		
		// Check multiple scopes
		if ( $auth->hasAllScopes( ['read', 'write'] ) ) {
			echo "User has full access";
		}
	}
	
	// Unified permission check (OAuth scope or WordPress capability)
	if ( $auth->userCan( 'admin', 'manage_options' ) ) {
		echo "User can perform admin actions";
	}
	
	// Get authentication method
	$method = $auth->getAuthenticationMethod(); // 'oauth', 'wordpress', or 'none'
	echo "Authenticated via: {$method}";
}

/**
 * Example 2: Client Management
 * 
 * Manage OAuth clients with proper dependency injection.
 */
function example_client_management() {
	$clients = OAuthPassport::clients();
	
	// Get client
	$client = $clients->getClient( 'my_client_id' );
	if ( $client ) {
		echo "Client: {$client['client_name']}";
	}
	
	// Check if client exists
	if ( $clients->clientExists( 'my_client_id' ) ) {
		echo "Client exists";
	}
	
	// Create new client
	try {
		$new_client = $clients->createClient([
			'client_name' => 'My Application',
			'redirect_uris' => ['https://myapp.com/callback'],
			'grant_types' => ['authorization_code', 'refresh_token'],
			'scope' => 'read write'
		]);
		
		echo "Created client: {$new_client['client_id']}";
		echo "Client secret: {$new_client['client_secret']}"; // Only shown once
		
		// Extract credentials for verification
		$client_id = $new_client['client_id'];
		$client_secret = $new_client['client_secret'];
		
		// Verify credentials
		if ( $clients->verifyCredentials( $client_id, $client_secret ) ) {
			echo "Valid credentials";
		}
		
	} catch ( \RuntimeException $e ) {
		echo "Failed to create client: {$e->getMessage()}";
	}
	
	// Get client metadata (without sensitive data)
	$metadata = $clients->getClientMetadata( 'my_client_id' );
	// client_secret and registration_access_token are automatically removed
}

/**
 * Example 3: URL Generation
 * 
 * Generate OAuth URLs with proper context awareness.
 */
function example_url_generation() {
	$urls = OAuthPassport::urls();
	
	// Basic authorization URL
	$auth_url = $urls->getAuthorizationUrl([
		'client_id' => 'my_client_id',
		'redirect_uri' => 'https://myapp.com/callback',
		'scope' => 'read write',
		'state' => 'random_state_value'
	]);
	
	// Complete authorization URL with PKCE
	$pkce_url = $urls->buildAuthorizationUrl(
		'my_client_id',
		'https://myapp.com/callback',
		'code_challenge_here',
		'state_value',
		'read write admin'
	);
	
	// Other endpoints
	$token_url = $urls->getTokenUrl();
	$registration_url = $urls->getRegistrationUrl();
	$jwks_url = $urls->getJwksUrl();
	
	// Get all endpoints at once
	$all_endpoints = $urls->getAllEndpoints();
	
	// Validate redirect URI
	if ( $urls->isValidRedirectUri( 'https://myapp.com/callback' ) ) {
		echo "Valid redirect URI";
	}
}

/**
 * Example 4: Token Operations
 * 
 * Handle token validation, refresh, and revocation.
 */
function example_token_operations() {
	$tokens = OAuthPassport::tokens();
	
	// Validate access token
	$token_data = $tokens->validateAccessToken( 'access_token_here' );
	if ( $token_data ) {
		echo "Valid token for user {$token_data->user_id}";
	}
	
	// Note: Token exchange is handled by the OAuth2Server, not TokenService
	// This would be done through the OAuth2Server's token endpoint
	echo "Token exchange is handled by OAuth2Server token endpoint";
	
	// Refresh token
	try {
		$refreshed = $tokens->refreshAccessToken(
			'refresh_token_here',
			'my_client_id',
			'client_secret_here'
		);
		
		echo "New access token: {$refreshed['access_token']}";
		
	} catch ( \Exception $e ) {
		echo "Token refresh failed: {$e->getMessage()}";
	}
	
	// Revoke token
	if ( $tokens->revokeToken( 'token_to_revoke' ) ) {
		echo "Token revoked successfully";
	}
	
	// Cleanup expired tokens
	$cleaned = $tokens->cleanupExpiredTokens();
	echo "Cleaned up {$cleaned} expired tokens";
}

/**
 * Example 5: Plugin-Level Operations
 * 
 * Use the main OAuthPassport class for plugin-wide operations.
 */
function example_plugin_operations() {
	// Check if OAuth is enabled
	if ( OAuthPassport::isEnabled() ) {
		echo "OAuth Passport is enabled";
	}
	
	// Get available scopes
	$scopes = OAuthPassport::getAvailableScopes();
	foreach ( $scopes as $scope => $description ) {
		echo "{$scope}: {$description}";
	}
	
	// Get default scopes
	$default_scopes = OAuthPassport::getDefaultScopes();
	echo "Default scopes: " . implode( ', ', $default_scopes );
	
	// Cleanup expired tokens
	$cleaned = OAuthPassport::cleanupExpiredTokens();
	echo "Cleaned up {$cleaned} expired tokens";
}

/**
 * Example 6: Performance Optimization
 * 
 * Cache context objects for better performance in loops or repeated calls.
 */
function example_performance_optimization() {
	// Cache contexts for repeated use
	$auth = OAuthPassport::auth();
	$clients = OAuthPassport::clients();
	$urls = OAuthPassport::urls();
	$tokens = OAuthPassport::tokens();
	
	// Now use cached instances
	for ( $i = 0; $i < 100; $i++ ) {
		if ( $auth->hasScope( 'read' ) ) {
			$client = $clients->getClient( "client_{$i}" );
			// Process client...
		}
	}
}

/**
 * Example 7: Testing with Dependency Injection
 * 
 * The clean architecture makes testing easy with mocked dependencies.
 */
function example_testing_setup() {
	// In tests, you can inject mock contexts
	// Note: This would be inside a test class method, not a standalone function
	// $mock_auth = $this->createMock( \OAuthPassport\Context\AuthenticationContext::class );
	// $mock_auth->method( 'hasScope' )->willReturn( true );
	
	echo "Testing setup - mock contexts would be created in test class methods";
	
	// Example of how you would use mocked context in actual tests:
	// OAuthPassport::setContext( 'auth', $mock_auth );
	// $has_scope = OAuthPassport::auth()->hasScope( 'read' ); // Returns true
	
	// Reset after test
	OAuthPassport::reset();
}

/**
 * Example 8: WordPress Integration
 * 
 * Integrate OAuth with WordPress hooks and filters.
 */
function example_wordpress_integration() {
	// Hook into WordPress actions
	add_action( 'rest_api_init', function() {
		// Register custom endpoint that requires OAuth
		register_rest_route( 'my-plugin/v1', '/protected', [
			'methods' => 'GET',
			'callback' => function( $request ) {
				$auth = OAuthPassport::auth();
				
				if ( ! $auth->userCan( 'read' ) ) {
					return new \WP_Error( 'oauth_insufficient_scope', 'Insufficient scope', ['status' => 403] );
				}
				
				return ['message' => 'Access granted'];
			}
		]);
	});
	
	// Filter OAuth scopes
	add_filter( 'oauth_passport_available_scopes', function( $scopes ) {
		$scopes['custom'] = 'Custom scope for my plugin';
		return $scopes;
	});
}
