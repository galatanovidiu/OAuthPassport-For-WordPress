<?php
/**
 * Unit tests for TokenRepository class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Repositories\TokenRepository;
use WP_UnitTestCase;

/**
 * Test TokenRepository class
 */
class TokenRepositoryTest extends WP_UnitTestCase
{
    /**
     * TokenRepository instance
     *
     * @var TokenRepository
     */
    private TokenRepository $repository;

    /**
     * Test client ID
     *
     * @var string
     */
    private string $test_client_id;

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
        
        $this->repository = new TokenRepository();
        $this->test_client_id = 'test_client_' . wp_generate_uuid4();
        $this->test_user_id = $this->factory->user->create();
    }

    /**
     * Test storing an access token
     */
    public function test_store_access_token(): void
    {
        $token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $result = $this->repository->storeAccessToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->assertTrue($result);
    }

    /**
     * Test validating an access token
     */
    public function test_validate_access_token(): void
    {
        $token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $stored_token = $this->repository->validateAccessToken($token);
        
        $this->assertNotNull($stored_token);
        $this->assertIsObject($stored_token);
        $this->assertEquals($this->test_client_id, $stored_token->client_id);
        $this->assertEquals($this->test_user_id, $stored_token->user_id);
        $this->assertEquals($token, $stored_token->token_value);
    }

    /**
     * Test getting an access token
     */
    public function test_get_access_token(): void
    {
        $token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $stored_token = $this->repository->getAccessToken($token);
        
        $this->assertNotNull($stored_token);
        $this->assertIsArray($stored_token);
        $this->assertEquals($token, $stored_token['token_value']);
        $this->assertEquals($this->test_client_id, $stored_token['client_id']);
        $this->assertEquals($this->test_user_id, $stored_token['user_id']);
    }

    /**
     * Test retrieving non-existent access token
     */
    public function test_get_nonexistent_access_token(): void
    {
        $token = $this->repository->getAccessToken('nonexistent_token');
        
        $this->assertNull($token);
    }

    /**
     * Test storing a refresh token
     */
    public function test_store_refresh_token(): void
    {
        $token = 'oauth_refresh_' . bin2hex(random_bytes(32));
        
        $result = $this->repository->storeRefreshToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read write',
            2592000
        );
        
        $this->assertTrue($result);
    }

    /**
     * Test getting a refresh token
     */
    public function test_get_refresh_token(): void
    {
        $token = 'oauth_refresh_' . bin2hex(random_bytes(32));
        
        $this->repository->storeRefreshToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read write',
            2592000
        );
        
        $stored_token = $this->repository->getRefreshToken($token);
        
        $this->assertNotNull($stored_token);
        $this->assertIsObject($stored_token);
        $this->assertEquals($token, $stored_token->token_value);
        $this->assertEquals($this->test_client_id, $stored_token->client_id);
    }

    /**
     * Test storing an authorization code
     */
    public function test_store_authorization_code(): void
    {
        $code = 'oauth_code_' . bin2hex(random_bytes(32));
        $code_challenge = \OAuthPassport\Tests\base64url_encode(hash('sha256', 'test_verifier', true));
        
        $result = $this->repository->storeAuthorizationCode(
            $code,
            $this->test_client_id,
            $this->test_user_id,
            $code_challenge,
            'read',
            300
        );
        
        $this->assertTrue($result);
    }

    /**
     * Test getting an authorization code
     */
    public function test_get_authorization_code(): void
    {
        $code = 'oauth_code_' . bin2hex(random_bytes(32));
        $code_challenge = \OAuthPassport\Tests\base64url_encode(hash('sha256', 'test_verifier', true));
        
        $this->repository->storeAuthorizationCode(
            $code,
            $this->test_client_id,
            $this->test_user_id,
            $code_challenge,
            'read',
            300
        );
        
        $stored_code = $this->repository->getAuthorizationCode($code);
        
        $this->assertNotNull($stored_code);
        $this->assertIsArray($stored_code);
        $this->assertEquals($code, $stored_code['token_value']);
        $this->assertEquals($this->test_client_id, $stored_code['client_id']);
        $this->assertEquals($code_challenge, $stored_code['code_challenge']);
    }

    /**
     * Test deleting a token
     */
    public function test_delete_token(): void
    {
        $token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $result = $this->repository->deleteToken($token);
        $this->assertTrue($result);
        
        // Verify token is deleted
        $deleted_token = $this->repository->getAccessToken($token);
        $this->assertNull($deleted_token);
    }

    /**
     * Test revoking an access token
     */
    public function test_revoke_access_token(): void
    {
        $token = 'oauth_access_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $result = $this->repository->revokeAccessToken($token);
        $this->assertTrue($result);
        
        // Verify token is revoked
        $revoked_token = $this->repository->getAccessToken($token);
        $this->assertNull($revoked_token);
    }

    /**
     * Test revoking a refresh token
     */
    public function test_revoke_refresh_token(): void
    {
        $token = 'oauth_refresh_' . bin2hex(random_bytes(32));
        
        $this->repository->storeRefreshToken(
            $token,
            $this->test_client_id,
            $this->test_user_id,
            'read write',
            2592000
        );
        
        $result = $this->repository->revokeRefreshToken($token);
        $this->assertTrue($result);
        
        // Verify token is revoked
        $revoked_token = $this->repository->getRefreshToken($token);
        $this->assertNull($revoked_token);
    }

    /**
     * Test consuming an authorization code
     */
    public function test_consume_authorization_code(): void
    {
        $code = 'oauth_code_' . bin2hex(random_bytes(32));
        $code_challenge = \OAuthPassport\Tests\base64url_encode(hash('sha256', 'test_verifier', true));
        
        $this->repository->storeAuthorizationCode(
            $code,
            $this->test_client_id,
            $this->test_user_id,
            $code_challenge,
            'read',
            300
        );
        
        $result = $this->repository->consumeAuthorizationCode($code);
        $this->assertTrue($result);
        
        // Verify code is consumed
        $consumed_code = $this->repository->getAuthorizationCode($code);
        $this->assertNull($consumed_code);
    }

    /**
     * Test cleanup of expired tokens
     */
    public function test_cleanup_expired_tokens(): void
    {
        global $wpdb;
        
        // Store a token that will expire immediately
        $expired_token = 'oauth_access_expired_' . bin2hex(random_bytes(32));
        $this->repository->storeAccessToken(
            $expired_token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            -1 // Already expired
        );
        
        // Store a valid token
        $valid_token = 'oauth_access_valid_' . bin2hex(random_bytes(32));
        $this->repository->storeAccessToken(
            $valid_token,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        // Run cleanup
        $deleted_count = $this->repository->cleanupExpiredTokens();
        
        // At least one token should be cleaned up
        $this->assertGreaterThanOrEqual(1, $deleted_count);
        
        // Valid token should still exist
        $stored_valid = $this->repository->getAccessToken($valid_token);
        $this->assertNotNull($stored_valid);
    }

    /**
     * Test getting user tokens
     */
    public function test_get_user_tokens(): void
    {
        $token1 = 'oauth_access_user1_' . bin2hex(random_bytes(32));
        $token2 = 'oauth_access_user2_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token1,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->repository->storeAccessToken(
            $token2,
            $this->test_client_id,
            $this->test_user_id,
            'write',
            3600
        );
        
        $user_tokens = $this->repository->getUserTokens($this->test_user_id);
        
        $this->assertIsArray($user_tokens);
        $this->assertGreaterThanOrEqual(2, count($user_tokens));
    }

    /**
     * Test getting client tokens
     */
    public function test_get_client_tokens(): void
    {
        $token1 = 'oauth_access_client1_' . bin2hex(random_bytes(32));
        $token2 = 'oauth_access_client2_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token1,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->repository->storeAccessToken(
            $token2,
            $this->test_client_id,
            $this->test_user_id + 1,
            'write',
            3600
        );
        
        $client_tokens = $this->repository->getClientTokens($this->test_client_id);
        
        $this->assertIsArray($client_tokens);
        $this->assertGreaterThanOrEqual(2, count($client_tokens));
    }

    /**
     * Test revoking all user tokens
     */
    public function test_revoke_all_user_tokens(): void
    {
        $token1 = 'oauth_access_revoke1_' . bin2hex(random_bytes(32));
        $token2 = 'oauth_access_revoke2_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token1,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->repository->storeAccessToken(
            $token2,
            'another_client',
            $this->test_user_id,
            'write',
            3600
        );
        
        $result = $this->repository->revokeAllUserTokens($this->test_user_id);
        $this->assertTrue($result);
        
        // Verify tokens are revoked
        $user_tokens = $this->repository->getUserTokens($this->test_user_id);
        $this->assertEmpty($user_tokens);
    }

    /**
     * Test revoking all client tokens
     */
    public function test_revoke_all_client_tokens(): void
    {
        $token1 = 'oauth_access_client_revoke1_' . bin2hex(random_bytes(32));
        $token2 = 'oauth_access_client_revoke2_' . bin2hex(random_bytes(32));
        
        $this->repository->storeAccessToken(
            $token1,
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->repository->storeAccessToken(
            $token2,
            $this->test_client_id,
            $this->test_user_id + 1,
            'write',
            3600
        );
        
        $result = $this->repository->revokeAllClientTokens($this->test_client_id);
        $this->assertTrue($result);
        
        // Verify tokens are revoked
        $client_tokens = $this->repository->getClientTokens($this->test_client_id);
        $this->assertEmpty($client_tokens);
    }

    /**
     * Test token statistics
     */
    public function test_get_token_statistics(): void
    {
        // Store various tokens
        $this->repository->storeAccessToken(
            'oauth_access_stats1_' . bin2hex(random_bytes(32)),
            $this->test_client_id,
            $this->test_user_id,
            'read',
            3600
        );
        
        $this->repository->storeRefreshToken(
            'oauth_refresh_stats1_' . bin2hex(random_bytes(32)),
            $this->test_client_id,
            $this->test_user_id,
            'read write',
            2592000
        );
        
        $stats = $this->repository->getTokenStatistics();
        
        $this->assertIsArray($stats);
        // The actual implementation returns token type counts
        $this->assertArrayHasKey('access', $stats);
        $this->assertArrayHasKey('refresh', $stats);
        $this->assertArrayHasKey('code', $stats);
        
        $this->assertGreaterThanOrEqual(1, $stats['access']);
        $this->assertGreaterThanOrEqual(1, $stats['refresh']);
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up test data
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE 'test_client_%'");
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE 'another_client'");
    }
}