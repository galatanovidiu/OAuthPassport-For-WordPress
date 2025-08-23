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
use Yoast\PHPUnitPolyfills\TestCases\TestCase;

/**
 * Test OAuth2Server class
 */
class OAuth2ServerTest extends WP_UnitTestCase
{
    /**
     * Test OAuth2Server instantiation
     */
    public function test_oauth2_server_instantiation(): void
    {
        // Skip test if OAuth is disabled
        if (!apply_filters('oauth_passport_enabled', true)) {
            $this->markTestSkipped('OAuth is disabled');
        }

        $server = new OAuth2Server();
        $this->assertInstanceOf(OAuth2Server::class, $server);
    }

    /**
     * Test that OAuth endpoints are registered
     */
    public function test_oauth_endpoints_registered(): void
    {
        // Skip test if OAuth is disabled
        if (!apply_filters('oauth_passport_enabled', true)) {
            $this->markTestSkipped('OAuth is disabled');
        }

        $server = new OAuth2Server();
        
        // Check if OAuth endpoints are registered
        $routes = rest_get_server()->get_routes();
        
        $this->assertArrayHasKey('/oauth/v2/', $routes);
        $this->assertArrayHasKey('/oauth/v2/authorize', $routes);
        $this->assertArrayHasKey('/oauth/v2/token', $routes);
    }
}
