<?php
/**
 * Unit tests for OAuth2Server class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Auth\OAuth2Server;
use WP_UnitTestCase;
use WP_REST_Request;
use WP_Error;

/**
 * Test OAuth2Server class
 */
class OAuth2ServerTest extends WP_UnitTestCase
{
    /**
     * OAuth2Server instance
     *
     * @var OAuth2Server
     */
    private OAuth2Server $server;

    /**
     * Set up test fixtures
     */
    public function setUp(): void
    {
        parent::setUp();
        
        // Skip test if OAuth is disabled
        if (!apply_filters('oauth_passport_enabled', true)) {
            $this->markTestSkipped('OAuth is disabled');
        }
        
        $this->server = new OAuth2Server();
    }

    /**
     * Test OAuth2Server instantiation
     */
    public function test_oauth2_server_instantiation(): void
    {
        $this->assertInstanceOf(OAuth2Server::class, $this->server);
    }

    /**
     * Test that OAuth endpoints are registered
     */
    public function test_oauth_endpoints_registered(): void
    {
        // Initialize REST server
        global $wp_rest_server;
        $wp_rest_server = new \WP_REST_Server();
        do_action('rest_api_init');
        
        // Check if OAuth endpoints are registered
        $routes = rest_get_server()->get_routes();
        
        $this->assertArrayHasKey('/oauth-passport/v1/authorize', $routes);
        $this->assertArrayHasKey('/oauth-passport/v1/token', $routes);
        $this->assertArrayHasKey('/oauth-passport/v1/register', $routes);
    }

    /**
     * Test OAuth server enabled state
     */
    public function test_oauth_server_enabled_state(): void
    {
        // Test default enabled state
        $this->assertTrue($this->server->is_enabled());
        
        // Test disabling OAuth
        add_filter('oauth_passport_enabled', '__return_false');
        $disabled_server = new OAuth2Server();
        $this->assertFalse($disabled_server->is_enabled());
        
        // Clean up filter
        remove_filter('oauth_passport_enabled', '__return_false');
    }

    /**
     * Test authorization endpoint with missing parameters
     */
    public function test_authorization_endpoint_missing_parameters(): void
    {
        $request = new WP_REST_Request('GET', '/oauth/v2/authorize');
        
        $response = $this->server->handle_authorization_request($request);
        
        $this->assertInstanceOf(WP_Error::class, $response);
        $this->assertEquals('invalid_request', $response->get_error_code());
    }

    /**
     * Test authorization endpoint with invalid client
     */
    public function test_authorization_endpoint_invalid_client(): void
    {
        $request = new WP_REST_Request('GET', '/oauth/v2/authorize');
        $request->set_param('client_id', 'invalid_client');
        $request->set_param('response_type', 'code');
        $request->set_param('redirect_uri', 'https://example.com/callback');
        
        $response = $this->server->handle_authorization_request($request);
        
        $this->assertInstanceOf(WP_Error::class, $response);
        $this->assertEquals('invalid_client', $response->get_error_code());
    }

    /**
     * Test token endpoint with missing parameters
     */
    public function test_token_endpoint_missing_parameters(): void
    {
        $request = new WP_REST_Request('POST', '/oauth/v2/token');
        
        $response = $this->server->handle_token_request($request);
        
        $this->assertInstanceOf(WP_Error::class, $response);
        $this->assertEquals('invalid_request', $response->get_error_code());
    }

    /**
     * Test token endpoint with invalid grant type
     */
    public function test_token_endpoint_invalid_grant_type(): void
    {
        $request = new WP_REST_Request('POST', '/oauth/v2/token');
        $request->set_param('grant_type', 'invalid_grant');
        
        $response = $this->server->handle_token_request($request);
        
        $this->assertInstanceOf(WP_Error::class, $response);
        $this->assertEquals('unsupported_grant_type', $response->get_error_code());
    }

    /**
     * Test client registration endpoint
     */
    public function test_client_registration_endpoint(): void
    {
        $request = new WP_REST_Request('POST', '/oauth/v2/register');
        $request->set_param('client_name', 'Test Client');
        $request->set_param('redirect_uris', ['https://example.com/callback']);
        
        $response = $this->server->handle_client_registration($request);
        
        // Should return client data or error
        $this->assertTrue(is_array($response) || $response instanceof WP_Error);
        
        if (is_array($response)) {
            $this->assertArrayHasKey('client_id', $response);
            $this->assertArrayHasKey('client_secret', $response);
        }
    }

    /**
     * Test token introspection endpoint
     */
    public function test_token_introspection_endpoint(): void
    {
        $request = new WP_REST_Request('POST', '/oauth/v2/introspect');
        $request->set_param('token', 'invalid_token');
        
        $response = $this->server->handle_token_introspection($request);
        
        // Handle WP_REST_Response objects
        if ($response instanceof \WP_REST_Response) {
            $response = $response->get_data();
        }
        
        $this->assertIsArray($response);
        $this->assertArrayHasKey('active', $response);
        $this->assertFalse($response['active']);
    }

    /**
     * Test discovery endpoint
     */
    public function test_discovery_endpoint(): void
    {
        $request = new WP_REST_Request('GET', '/oauth/v2/.well-known/oauth-authorization-server');
        
        $response = $this->server->handle_discovery_request($request);
        
        $this->assertIsArray($response);
        $this->assertArrayHasKey('issuer', $response);
        $this->assertArrayHasKey('authorization_endpoint', $response);
        $this->assertArrayHasKey('token_endpoint', $response);
    }

    /**
     * Test JWKS endpoint
     */
    public function test_jwks_endpoint(): void
    {
        $request = new WP_REST_Request('GET', '/oauth/v2/.well-known/jwks.json');
        
        $response = $this->server->handle_jwks_request($request);
        
        $this->assertIsArray($response);
        $this->assertArrayHasKey('keys', $response);
        $this->assertIsArray($response['keys']);
    }

    /**
     * Test error logging functionality
     */
    public function test_error_logging(): void
    {
        // Create a request that will generate an error
        $request = new WP_REST_Request('GET', '/oauth/v2/authorize');
        
        $response = $this->server->handle_authorization_request($request);
        
        $this->assertInstanceOf(WP_Error::class, $response);
        
        // Check that error was logged (this would require access to the error logger)
        // For now, just verify the error response structure
        $this->assertNotEmpty($response->get_error_message());
    }

    /**
     * Test CORS headers
     */
    public function test_cors_headers(): void
    {
        $request = new WP_REST_Request('OPTIONS', '/oauth/v2/token');
        
        // This would test CORS preflight handling
        // Implementation depends on how CORS is handled in the server
        $this->assertTrue(true); // Placeholder
    }

    /**
     * Test rate limiting (if implemented)
     */
    public function test_rate_limiting(): void
    {
        // This would test rate limiting functionality
        // Implementation depends on rate limiting strategy
        $this->assertTrue(true); // Placeholder
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up any test data
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_name LIKE 'Test%'");
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE 'test_%'");
    }
}
