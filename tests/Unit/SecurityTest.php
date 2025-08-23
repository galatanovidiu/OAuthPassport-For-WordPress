<?php
/**
 * Security Classes Unit Tests
 *
 * Tests for SecureTokenGenerator, ClientSecretManager, and SecurityUtils classes.
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

namespace OAuthPassport\Tests\Unit;

use WP_UnitTestCase;
use OAuthPassport\Auth\SecureTokenGenerator;
use OAuthPassport\Auth\ClientSecretManager;
use OAuthPassport\Auth\SecurityUtils;

/**
 * Class SecurityTest
 *
 * Comprehensive tests for security classes to ensure cryptographic security.
 */
class SecurityTest extends WP_UnitTestCase {

	/**
	 * SecureTokenGenerator instance
	 *
	 * @var SecureTokenGenerator
	 */
	private SecureTokenGenerator $token_generator;

	/**
	 * ClientSecretManager instance
	 *
	 * @var ClientSecretManager
	 */
	private ClientSecretManager $secret_manager;

	/**
	 * Set up test fixtures
	 */
	public function setUp(): void {
		parent::setUp();
		$this->token_generator = new SecureTokenGenerator();
		$this->secret_manager = new ClientSecretManager();
	}

	/**
	 * Test secure token generation
	 */
	public function test_secure_token_generation(): void {
		// Test access token generation
		$token1 = $this->token_generator->generateAccessToken();
		$token2 = $this->token_generator->generateAccessToken();

		$this->assertNotEquals( $token1, $token2, 'Generated tokens should be unique' );
		$this->assertStringStartsWith( 'oauth_access_', $token1, 'Access token should have correct prefix' );
		$this->assertTrue( $this->token_generator->validateTokenStrength( $token1 ), 'Token should meet strength requirements' );

		// Test refresh token generation
		$refresh1 = $this->token_generator->generateRefreshToken();
		$refresh2 = $this->token_generator->generateRefreshToken();

		$this->assertNotEquals( $refresh1, $refresh2, 'Generated refresh tokens should be unique' );
		$this->assertStringStartsWith( 'oauth_refresh_', $refresh1, 'Refresh token should have correct prefix' );
		$this->assertTrue( $this->token_generator->validateTokenStrength( $refresh1 ), 'Refresh token should meet strength requirements' );

		// Test authorization code generation
		$code1 = $this->token_generator->generateAuthCode();
		$code2 = $this->token_generator->generateAuthCode();

		$this->assertNotEquals( $code1, $code2, 'Generated auth codes should be unique' );
		$this->assertStringStartsWith( 'oauth_code_', $code1, 'Auth code should have correct prefix' );
		$this->assertTrue( $this->token_generator->validateTokenStrength( $code1 ), 'Auth code should meet strength requirements' );
	}

	/**
	 * Test client secret generation and validation
	 */
	public function test_client_secret_generation(): void {
		$secret1 = $this->token_generator->generateClientSecret();
		$secret2 = $this->token_generator->generateClientSecret();

		$this->assertNotEquals( $secret1, $secret2, 'Generated client secrets should be unique' );
		$this->assertGreaterThanOrEqual( 64, strlen( $secret1 ), 'Client secret should be at least 64 characters' );

		// Test base64 encoding
		$decoded = base64_decode( $secret1, true );
		$this->assertNotFalse( $decoded, 'Client secret should be valid base64' );
		$this->assertEquals( 64, strlen( $decoded ), 'Decoded secret should be 64 bytes' );
	}

	/**
	 * Test token strength validation
	 */
	public function test_token_strength_validation(): void {
		// Valid tokens
		$valid_token = $this->token_generator->generateAccessToken();
		$this->assertTrue( $this->token_generator->validateTokenStrength( $valid_token ), 'Generated token should be valid' );

		// Invalid tokens
		$this->assertFalse( $this->token_generator->validateTokenStrength( 'short' ), 'Short token should be invalid' );
		$this->assertFalse( $this->token_generator->validateTokenStrength( 'oauth_invalid_chars_!' ), 'Token with invalid chars should be invalid' );
		$this->assertFalse( $this->token_generator->validateTokenStrength( 'oauth_odd_hex_length_123' ), 'Token with odd hex length should be invalid' );
	}

	/**
	 * Test entropy analysis
	 */
	public function test_token_entropy(): void {
		$token = $this->token_generator->generateAccessToken();
		$entropy = $this->token_generator->getTokenEntropy( $token );

		$this->assertTrue( $entropy['valid'], 'Token should be valid' );
		$this->assertEquals( 256, $entropy['entropy_bits'], 'Access token should have 256 bits of entropy' );
		$this->assertEquals( 32, $entropy['entropy_bytes'], 'Access token should have 32 bytes of entropy' );
		$this->assertEquals( 64, $entropy['hex_length'], 'Access token hex part should be 64 characters' );
	}

	/**
	 * Test client secret hashing
	 */
	public function test_client_secret_hashing(): void {
		$secret = $this->secret_manager->generateClientSecret();
		$hash = $this->secret_manager->hashClientSecret( $secret );

		// Test hash format
		$this->assertStringStartsWith( '$argon2', $hash, 'Hash should use Argon2' );
		$this->assertNotEquals( $secret, $hash, 'Hash should not equal plain text' );

		// Test verification
		$this->assertTrue( $this->secret_manager->verifyClientSecret( $secret, $hash ), 'Correct secret should verify' );
		$this->assertFalse( $this->secret_manager->verifyClientSecret( 'wrong_secret', $hash ), 'Wrong secret should not verify' );
	}

	/**
	 * Test client secret rehashing
	 */
	public function test_client_secret_rehashing(): void {
		$secret = $this->secret_manager->generateClientSecret();
		$hash = $this->secret_manager->hashClientSecret( $secret );

		// Fresh hash should not need rehashing
		$this->assertFalse( $this->secret_manager->needsRehash( $hash ), 'Fresh hash should not need rehashing' );

		// Legacy hash should need rehashing
		$legacy_hash = wp_hash( $secret );
		$this->assertTrue( $this->secret_manager->needsRehash( $legacy_hash ), 'Legacy hash should need rehashing' );
	}

	/**
	 * Test legacy hash migration
	 */
	public function test_legacy_hash_migration(): void {
		$secret = 'test_secret_12345678901234567890123456789012'; // 32+ chars
		$legacy_hash = wp_hash( $secret );

		// Test migration
		$new_hash = $this->secret_manager->migrateLegacyHash( $secret, $legacy_hash );
		$this->assertNotNull( $new_hash, 'Migration should succeed with correct secret' );
		$this->assertStringStartsWith( '$argon2', $new_hash, 'Migrated hash should use Argon2' );

		// Test failed migration with wrong secret
		$failed_migration = $this->secret_manager->migrateLegacyHash( 'wrong_secret', $legacy_hash );
		$this->assertNull( $failed_migration, 'Migration should fail with wrong secret' );
	}

	/**
	 * Test timing-safe string comparison
	 */
	public function test_timing_safe_comparison(): void {
		$known = 'known_string_123';
		$correct = 'known_string_123';
		$incorrect = 'wrong_string_456';

		$this->assertTrue( SecurityUtils::secureCompare( $known, $correct ), 'Identical strings should match' );
		$this->assertFalse( SecurityUtils::secureCompare( $known, $incorrect ), 'Different strings should not match' );

		// Test with empty strings
		$this->assertTrue( SecurityUtils::secureCompare( '', '' ), 'Empty strings should match' );
		$this->assertFalse( SecurityUtils::secureCompare( $known, '' ), 'Non-empty and empty should not match' );
	}

	/**
	 * Test token validation
	 */
	public function test_token_validation(): void {
		$token = $this->token_generator->generateAccessToken();

		$this->assertTrue( SecurityUtils::validateToken( $token, $token ), 'Token should validate against itself' );
		$this->assertFalse( SecurityUtils::validateToken( $token, 'different_token' ), 'Token should not validate against different token' );
		$this->assertFalse( SecurityUtils::validateToken( '', $token ), 'Empty provided token should not validate' );
		$this->assertFalse( SecurityUtils::validateToken( $token, '' ), 'Empty stored token should not validate' );
	}

	/**
	 * Test OAuth parameter sanitization
	 */
	public function test_oauth_param_sanitization(): void {
		$clean_param = 'valid_param-123.test';
		$dirty_param = 'invalid<script>alert("xss")</script>param';

		$this->assertEquals( $clean_param, SecurityUtils::sanitizeOAuthParam( $clean_param ), 'Clean param should remain unchanged' );
		$this->assertEquals( 'invalidscriptalertxssscriptparam', SecurityUtils::sanitizeOAuthParam( $dirty_param ), 'Dirty param should be sanitized' );
	}

	/**
	 * Test OAuth parameter validation
	 */
	public function test_oauth_param_validation(): void {
		$this->assertTrue( SecurityUtils::isValidOAuthParam( 'valid_param-123' ), 'Valid param should pass validation' );
		$this->assertFalse( SecurityUtils::isValidOAuthParam( 'invalid<param>' ), 'Invalid param should fail validation' );
		$this->assertFalse( SecurityUtils::isValidOAuthParam( 'param with spaces' ), 'Param with spaces should fail validation' );
	}

	/**
	 * Test secure redirect URI validation
	 */
	public function test_secure_redirect_uri_validation(): void {
		// Valid HTTPS URIs
		$this->assertTrue( SecurityUtils::isSecureRedirectUri( 'https://example.com/callback' ), 'HTTPS URI should be valid' );
		$this->assertTrue( SecurityUtils::isSecureRedirectUri( 'https://subdomain.example.com/path' ), 'HTTPS subdomain URI should be valid' );

		// Valid localhost URIs (for development)
		$this->assertTrue( SecurityUtils::isSecureRedirectUri( 'http://localhost:3000/callback' ), 'Localhost HTTP should be valid' );
		$this->assertTrue( SecurityUtils::isSecureRedirectUri( 'http://127.0.0.1:8080/callback' ), 'Local IP HTTP should be valid' );

		// Invalid URIs
		$this->assertFalse( SecurityUtils::isSecureRedirectUri( 'http://example.com/callback' ), 'HTTP non-localhost should be invalid' );
		$this->assertFalse( SecurityUtils::isSecureRedirectUri( 'javascript:alert("xss")' ), 'JavaScript URI should be invalid' );
		$this->assertFalse( SecurityUtils::isSecureRedirectUri( 'not-a-uri' ), 'Invalid URI format should be invalid' );
	}

	/**
	 * Test localhost detection
	 */
	public function test_localhost_detection(): void {
		$this->assertTrue( SecurityUtils::isLocalhostHost( 'localhost' ), 'localhost should be detected' );
		$this->assertTrue( SecurityUtils::isLocalhostHost( '127.0.0.1' ), '127.0.0.1 should be detected' );
		$this->assertTrue( SecurityUtils::isLocalhostHost( '::1' ), '::1 should be detected' );
		$this->assertTrue( SecurityUtils::isLocalhostHost( 'test.local' ), '.local domain should be detected' );

		$this->assertFalse( SecurityUtils::isLocalhostHost( 'example.com' ), 'External domain should not be detected as localhost' );
		$this->assertFalse( SecurityUtils::isLocalhostHost( '8.8.8.8' ), 'Public IP should not be detected as localhost' );
	}

	/**
	 * Test state parameter generation and validation
	 */
	public function test_state_parameter(): void {
		$state1 = SecurityUtils::generateState();
		$state2 = SecurityUtils::generateState();

		$this->assertNotEquals( $state1, $state2, 'Generated states should be unique' );
		$this->assertTrue( SecurityUtils::isValidState( $state1 ), 'Generated state should be valid' );
		$this->assertEquals( 64, strlen( $state1 ), 'State should be 64 characters (32 bytes hex)' );

		// Test invalid states
		$this->assertFalse( SecurityUtils::isValidState( 'short' ), 'Short state should be invalid' );
		$this->assertFalse( SecurityUtils::isValidState( 'invalid_chars_!' ), 'State with invalid chars should be invalid' );
	}

	/**
	 * Test array comparison
	 */
	public function test_secure_array_compare(): void {
		$array1 = array( 'key1' => 'value1', 'key2' => 'value2' );
		$array2 = array( 'key1' => 'value1', 'key2' => 'value2' );
		$array3 = array( 'key1' => 'value1', 'key2' => 'different' );
		$array4 = array( 'key2' => 'value2', 'key1' => 'value1' ); // Different order

		$this->assertTrue( SecurityUtils::secureArrayCompare( $array1, $array2 ), 'Identical arrays should match' );
		$this->assertTrue( SecurityUtils::secureArrayCompare( $array1, $array4 ), 'Arrays with same content but different order should match' );
		$this->assertFalse( SecurityUtils::secureArrayCompare( $array1, $array3 ), 'Arrays with different values should not match' );
	}

	/**
	 * Test random source availability
	 */
	public function test_random_source_availability(): void {
		$this->assertTrue( $this->token_generator->hasSecureRandomSource(), 'System should have secure random source' );

		$info = $this->token_generator->getRandomSourceInfo();
		$this->assertTrue( $info['has_secure_source'], 'Random source info should confirm availability' );
		$this->assertTrue( $info['random_bytes_available'], 'random_bytes should be available' );
	}

	/**
	 * Test hash information analysis
	 */
	public function test_hash_info_analysis(): void {
		$secret = $this->secret_manager->generateClientSecret();
		$argon2_hash = $this->secret_manager->hashClientSecret( $secret );
		$legacy_hash = wp_hash( $secret );

		// Test Argon2 hash info
		$argon2_info = $this->secret_manager->getHashInfo( $argon2_hash );
		$this->assertStringContainsString( 'argon2', $argon2_info['algorithm'], 'Should detect Argon2 algorithm' );
		$this->assertFalse( $argon2_info['is_legacy'], 'Argon2 hash should not be legacy' );

		// Test legacy hash info
		$legacy_info = $this->secret_manager->getHashInfo( $legacy_hash );
		$this->assertEquals( 'wp_hash', $legacy_info['algorithm'], 'Should detect wp_hash algorithm' );
		$this->assertTrue( $legacy_info['is_legacy'], 'wp_hash should be legacy' );
		$this->assertTrue( $legacy_info['needs_rehash'], 'Legacy hash should need rehashing' );
	}

	/**
	 * Test algorithm information
	 */
	public function test_algorithm_info(): void {
		$info = $this->secret_manager->getAlgorithmInfo();

		$this->assertIsArray( $info['available_algorithms'], 'Should return available algorithms' );
		$this->assertNotEmpty( $info['recommended_algorithm'], 'Should have recommended algorithm' );
		$this->assertContains( $info['recommended_algorithm'], $info['available_algorithms'], 'Recommended algorithm should be available' );
	}

	/**
	 * Test error handling for invalid inputs
	 */
	public function test_error_handling(): void {
		// Test invalid token generation parameters
		$this->expectException( \InvalidArgumentException::class );
		$this->token_generator->generateToken( 'test', 0 ); // Zero entropy should throw exception
	}

	/**
	 * Test client secret strength requirements
	 */
	public function test_client_secret_strength_requirements(): void {
		// Test weak secret rejection
		$this->expectException( \InvalidArgumentException::class );
		$this->secret_manager->hashClientSecret( 'weak' ); // Too short should throw exception
	}

	/**
	 * Test constant-time operations
	 */
	public function test_constant_time_operations(): void {
		$str1 = 'test_string_123';
		$str2 = 'test_string_123';
		$str3 = 'different_string';

		$this->assertTrue( SecurityUtils::constantTimeLengthEquals( $str1, $str2 ), 'Same length strings should match' );
		$this->assertFalse( SecurityUtils::constantTimeLengthEquals( $str1, $str3 ), 'Different length strings should not match' );
	}

	/**
	 * Test URL-safe string generation
	 */
	public function test_url_safe_string_generation(): void {
		$url_safe = $this->token_generator->generateUrlSafeString( 32 );

		$this->assertEquals( 43, strlen( $url_safe ), 'URL-safe string should be base64url encoded' ); // 32 bytes -> ~43 chars
		$this->assertDoesNotMatchRegularExpression( '/[+\/=]/', $url_safe, 'URL-safe string should not contain +, /, or =' );
		$this->assertMatchesRegularExpression( '/^[A-Za-z0-9_-]+$/', $url_safe, 'URL-safe string should only contain valid base64url chars' );
	}

	/**
	 * Test logging hash function
	 */
	public function test_logging_hash(): void {
		$sensitive_data = 'very_sensitive_secret_data';
		$hash1 = SecurityUtils::hashForLogging( $sensitive_data );
		$hash2 = SecurityUtils::hashForLogging( $sensitive_data );

		$this->assertEquals( $hash1, $hash2, 'Same data should produce same hash' );
		$this->assertEquals( 16, strlen( $hash1 ), 'Hash should be 16 characters' );
		$this->assertNotEquals( $sensitive_data, $hash1, 'Hash should not equal original data' );
	}
}
