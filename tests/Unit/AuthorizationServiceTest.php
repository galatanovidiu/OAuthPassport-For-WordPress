<?php
/**
 * Unit tests for AuthorizationService class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Services\AuthorizationService;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Repositories\TokenRepository;
use OAuthPassport\Repositories\ClientRepository;
use OAuthPassport\Auth\ScopeManager;
use WP_UnitTestCase;

/**
 * Test AuthorizationService class
 */
class AuthorizationServiceTest extends WP_UnitTestCase
{
    /**
     * AuthorizationService instance
     *
     * @var AuthorizationService
     */
    private AuthorizationService $service;

    /**
     * Dependencies
     */
    private SecureTokenGenerator $token_generator;
    private TokenRepository $token_repository;
    private ClientRepository $client_repository;
    private ScopeManager $scope_manager;

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
        $this->scope_manager = new ScopeManager();
        
        $this->service = new AuthorizationService(
            $this->token_generator,
            $this->token_repository,
            $this->client_repository,
            $this->scope_manager
        );
        
        $this->test_user_id = $this->factory->user->create();
        
        // Create test client
        $this->test_client = [
            'client_id' => 'test_client_' . wp_generate_uuid4(),
            'client_secret_hash' => password_hash('test_secret_long_enough_32chars', PASSWORD_ARGON2ID),
            'client_name' => 'Test Authorization Client',
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
     * Test generating authorization code
     */
    public function test_generate_authorization_code(): void
    {
        $scope = 'read';
        $code_challenge = \OAuthPassport\Tests\base64url_encode(hash('sha256', 'test_verifier', true));
        
        $result = $this->service->generateAuthorizationCode(
            $this->test_client['client_id'],
            $this->test_user_id,
            $code_challenge,
            $scope
        );
        
        $this->assertIsString($result);
        $this->assertStringStartsWith('oauth_code_', $result);
    }

    /**
     * Test generating authorization code with invalid client
     */
    public function test_generate_authorization_code_invalid_client(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid client ID');
        
        $this->service->generateAuthorizationCode(
            'invalid_client',
            $this->test_user_id,
            'challenge_code',
            'read'
        );
    }

    /**
     * Test exchanging authorization code for tokens
     */
    public function test_exchange_authorization_code(): void
    {
        $scope = 'read';
        $code_verifier = 'test_verifier_' . bin2hex(random_bytes(16));
        $code_challenge = \OAuthPassport\Tests\base64url_encode(hash('sha256', $code_verifier, true));
        
        // Generate code first
        $auth_code = $this->service->generateAuthorizationCode(
            $this->test_client['client_id'],
            $this->test_user_id,
            $code_challenge,
            $scope
        );
        
        // Exchange code for tokens
        $result = $this->service->exchangeAuthorizationCode(
            $auth_code,
            $this->test_client['client_id'],
            $code_verifier
        );
        
        $this->assertIsArray($result);
        $this->assertArrayHasKey('access_token', $result);
        $this->assertArrayHasKey('refresh_token', $result);
        $this->assertArrayHasKey('expires_in', $result);
    }

    /**
     * Test validating redirect URI 
     */
    public function test_validate_redirect_uri(): void
    {
        // Test valid redirect URI
        $valid_result = $this->service->validateRedirectUri(
            $this->test_client,
            'https://example.com/callback'
        );
        $this->assertTrue($valid_result);
        
        // Test invalid redirect URI
        $invalid_result = $this->service->validateRedirectUri(
            $this->test_client,
            'https://malicious.com/callback'
        );
        $this->assertFalse($invalid_result);
    }

    /**
     * Test user authorization status
     */
    public function test_user_authorization_status(): void
    {
        // Initially user should not have authorized the client
        $initial_status = $this->service->hasUserAuthorizedClient(
            $this->test_user_id,
            $this->test_client['client_id']
        );
        $this->assertFalse($initial_status);
        
        // Store user authorization
        $store_result = $this->service->storeUserAuthorization(
            $this->test_user_id,
            $this->test_client['client_id']
        );
        $this->assertTrue($store_result);
        
        // Now user should have authorized the client
        $authorized_status = $this->service->hasUserAuthorizedClient(
            $this->test_user_id,
            $this->test_client['client_id']
        );
        $this->assertTrue($authorized_status);
    }

    /**
     * Test process user consent
     */
    public function test_process_user_consent_granted(): void
    {
        $params = [
            'client_id' => $this->test_client['client_id'],
            'response_type' => 'code',
            'redirect_uri' => 'https://example.com/callback',
            'scope' => 'read',
            'state' => 'test_state',
            'code_challenge' => \OAuthPassport\Tests\base64url_encode(hash('sha256', 'test_verifier', true)),
            'code_challenge_method' => 'S256'
        ];
        
        $result = $this->service->processUserConsent(
            $this->test_user_id,
            $params,
            true
        );
        
        $this->assertIsArray($result);
        $this->assertArrayHasKey('code', $result);
        $this->assertArrayHasKey('state', $result);
        $this->assertEquals('test_state', $result['state']);
    }

    /**
     * Test process user consent denied
     */
    public function test_process_user_consent_denied(): void
    {
        $params = [
            'client_id' => $this->test_client['client_id'],
            'response_type' => 'code',
            'redirect_uri' => 'https://example.com/callback',
            'scope' => 'read',
            'state' => 'test_state'
        ];
        
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('User denied authorization');
        
        $this->service->processUserConsent(
            $this->test_user_id,
            $params,
            false
        );
    }

    /**
     * Test scope validation
     */
    public function test_validate_scope(): void
    {
        // Test with client array (actual implementation signature)
        $valid_result = $this->service->validateScope('read', $this->test_client);
        $this->assertTrue($valid_result);
        
        // Test empty scope
        $empty_result = $this->service->validateScope('', $this->test_client);
        $this->assertTrue($empty_result);
    }

    /**
     * Test format error response
     */
    public function test_format_error_response(): void
    {
        $error_response = $this->service->formatErrorResponse(
            'invalid_client',
            'Client authentication failed',
            'test_state'
        );
        
        $this->assertIsArray($error_response);
        $this->assertEquals('invalid_client', $error_response['error']);
        $this->assertEquals('Client authentication failed', $error_response['error_description']);
        $this->assertEquals('test_state', $error_response['state']);
    }

    /**
     * Clean up after tests
     */
    public function tearDown(): void
    {
        parent::tearDown();
        
        // Clean up test data
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_clients WHERE client_id LIKE 'test_client_%'");
        $wpdb->query("DELETE FROM {$wpdb->prefix}oauth_passport_tokens WHERE client_id LIKE 'test_client_%'");
    }
}