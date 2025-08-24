<?php
/**
 * Unit tests for TokenService class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Services\TokenService;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Auth\ClientSecretManager;
use WP_UnitTestCase;

/**
 * Test TokenService class - focusing only on implemented methods
 */
class TokenServiceTest extends WP_UnitTestCase
{
    /**
     * TokenService instance
     *
     * @var TokenService
     */
    private TokenService $service;

    /**
     * Dependencies
     */
    private SecureTokenGenerator $token_generator;
    private TokenRepository $token_repository;
    private ClientRepository $client_repository;
    private ClientSecretManager $secret_manager;

    /**
     * Test client data
     *
     * @var array
     */
    private array $test_client;

    /**
     * Test user ID
     *
     * @var int
     */
    private int $test_user_id;

    /**
     * Set up test fixtures
     */
    public function setUp(): void
    {
        parent::setUp();
        
        $this->token_generator = new SecureTokenGenerator();
        $this->token_repository = new TokenRepository();
        $this->client_repository = new ClientRepository();
        $this->secret_manager = new ClientSecretManager();
        
        $this->service = new TokenService(
            $this->token_generator,
            $this->token_repository,
            $this->client_repository,
            $this->secret_manager
        );
        
        $this->test_user_id = $this->factory->user->create();
        
        // Create test client
        $this->test_client = [
            'client_id' => 'test_token_client_' . wp_generate_uuid4(),
            'client_secret_hash' => password_hash('test_secret_long_enough_32chars_min', PASSWORD_ARGON2ID),
            'client_name' => 'Test Token Client',
            'redirect_uris' => ['https://example.com/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'scope' => 'read write',
            'is_confidential' => true,
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ];
        
        $this->client_repository->storeClient($this->test_client);
    }

    /**
     * Test validating access token
     */
    public function test_validate_access_token(): void
    {
        // Create a token directly in repository
        $access_token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeAccessToken(
            $access_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            3600
        );
        
        $validation_result = $this->service->validateAccessToken($access_token);
        
        $this->assertIsObject($validation_result);
        $this->assertEquals($this->test_client['client_id'], $validation_result->client_id);
        $this->assertEquals($this->test_user_id, $validation_result->user_id);
        $this->assertEquals($access_token, $validation_result->token_value);
    }

    /**
     * Test validating invalid access token
     */
    public function test_validate_invalid_access_token(): void
    {
        $validation_result = $this->service->validateAccessToken('invalid_token');
        
        $this->assertNull($validation_result);
    }

    /**
     * Test validating expired access token
     */
    public function test_validate_expired_access_token(): void
    {
        // Create expired token directly in repository
        $expired_token = 'oauth_access_expired_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeAccessToken(
            $expired_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            -1 // Already expired
        );
        
        $validation_result = $this->service->validateAccessToken($expired_token);
        
        $this->assertNull($validation_result);
    }

    /**
     * Test refreshing access token
     */
    public function test_refresh_access_token(): void
    {
        // Create refresh token directly in repository
        $refresh_token = 'oauth_refresh_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeRefreshToken(
            $refresh_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read write',
            2592000 // 30 days
        );
        
        // Refresh the tokens
        $refreshed_tokens = $this->service->refreshAccessToken(
            $refresh_token,
            $this->test_client['client_id'],
            'test_secret_long_enough_32chars_min'
        );
        
        $this->assertIsArray($refreshed_tokens);
        $this->assertArrayHasKey('access_token', $refreshed_tokens);
        $this->assertArrayHasKey('refresh_token', $refreshed_tokens);
        $this->assertArrayHasKey('token_type', $refreshed_tokens);
        $this->assertArrayHasKey('expires_in', $refreshed_tokens);
        
        $this->assertEquals('Bearer', $refreshed_tokens['token_type']);
        $this->assertStringStartsWith('oauth_access_', $refreshed_tokens['access_token']);
        $this->assertStringStartsWith('oauth_refresh_', $refreshed_tokens['refresh_token']);
    }

    /**
     * Test refreshing with invalid refresh token
     */
    public function test_refresh_with_invalid_token(): void
    {
        $this->expectException(\Exception::class);
        
        $this->service->refreshAccessToken(
            'invalid_refresh_token', 
            $this->test_client['client_id'],
            'test_secret_long_enough_32chars_min'
        );
    }

    /**
     * Test refreshing with wrong client
     */
    public function test_refresh_with_wrong_client(): void
    {
        // Create refresh token
        $refresh_token = 'oauth_refresh_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeRefreshToken(
            $refresh_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            2592000
        );
        
        $this->expectException(\Exception::class);
        
        $this->service->refreshAccessToken(
            $refresh_token, 
            'wrong_client_id',
            'test_secret_long_enough_32chars_min'
        );
    }

    /**
     * Test revoking token
     */
    public function test_revoke_token(): void
    {
        // Create token directly in repository
        $access_token = 'oauth_access_revoke_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeAccessToken(
            $access_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            3600
        );
        
        // Revoke token
        $result = $this->service->revokeToken($access_token);
        
        $this->assertTrue($result);
        
        // Token should no longer be valid
        $validation_result = $this->service->validateAccessToken($access_token);
        $this->assertNull($validation_result);
    }

    /**
     * Test revoking non-existent token - current implementation returns true
     */
    public function test_revoke_nonexistent_token(): void
    {
        $result = $this->service->revokeToken('nonexistent_token');
        
        // Current implementation returns true even for nonexistent tokens
        $this->assertTrue($result);
    }

    /**
     * Test token cleanup
     */
    public function test_cleanup_expired_tokens(): void
    {
        // Create expired token
        $expired_token = 'oauth_access_cleanup_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeAccessToken(
            $expired_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            -7200 // Expired 2 hours ago
        );
        
        // Create valid token
        $valid_token = 'oauth_access_valid_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeAccessToken(
            $valid_token,
            $this->test_client['client_id'],
            $this->test_user_id,
            'read',
            3600
        );
        
        // Run cleanup
        $cleaned_count = $this->service->cleanupExpiredTokens();
        
        $this->assertGreaterThanOrEqual(1, $cleaned_count);
        
        // Expired token should be gone
        $this->assertNull($this->token_repository->getAccessToken($expired_token));
        
        // Valid token should remain
        $this->assertNotNull($this->token_repository->getAccessToken($valid_token));
    }

    /**
     * Test service instantiation
     */
    public function test_service_instantiation(): void
    {
        $this->assertInstanceOf(TokenService::class, $this->service);
    }

    /**
     * Test with public client (no client secret)
     */
    public function test_refresh_token_public_client(): void
    {
        // Create public client
        $public_client = [
            'client_id' => 'public_client_' . wp_generate_uuid4(),
            'client_secret_hash' => null,
            'client_name' => 'Public Test Client',
            'redirect_uris' => ['https://example.com/callback'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'response_types' => ['code'],
            'scope' => 'read',
            'is_confidential' => false,
            'created_at' => current_time('mysql'),
            'updated_at' => current_time('mysql')
        ];
        
        $this->client_repository->storeClient($public_client);
        
        // Create refresh token for public client
        $refresh_token = 'oauth_refresh_public_' . bin2hex(random_bytes(32));
        
        $this->token_repository->storeRefreshToken(
            $refresh_token,
            $public_client['client_id'],
            $this->test_user_id,
            'read',
            2592000
        );
        
        // Refresh without client secret (public client)
        $refreshed_tokens = $this->service->refreshAccessToken(
            $refresh_token,
            $public_client['client_id']
        );
        
        $this->assertIsArray($refreshed_tokens);
        $this->assertArrayHasKey('access_token', $refreshed_tokens);
        $this->assertArrayHasKey('refresh_token', $refreshed_tokens);
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up test data
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_id LIKE 'test_token_client_%' OR client_id LIKE 'public_client_%'");
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE 'test_token_client_%' OR client_id LIKE 'public_client_%'");
    }
}