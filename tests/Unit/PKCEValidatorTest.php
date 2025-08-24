<?php
/**
 * Unit tests for PKCEValidator class
 *
 * @package OAuthPassport
 * @subpackage Tests
 */

declare(strict_types=1);

namespace OAuthPassport\Tests\Unit;

use OAuthPassport\Auth\PKCEValidator;
use WP_UnitTestCase;

/**
 * Test PKCEValidator class
 */
class PKCEValidatorTest extends WP_UnitTestCase
{
    /**
     * Test valid PKCE validation with S256
     */
    public function test_validate_pkce_s256_valid(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        $challenge = PKCEValidator::generate_challenge($verifier, 'S256');
        
        $result = PKCEValidator::validate($challenge, $verifier, 'S256');
        $this->assertTrue($result);
    }

    /**
     * Test invalid PKCE validation with wrong verifier
     */
    public function test_validate_pkce_s256_invalid(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        $wrong_verifier = 'wrong_verifier_43_characters_minimum_length_def456';
        $challenge = PKCEValidator::generate_challenge($verifier, 'S256');
        
        $result = PKCEValidator::validate($challenge, $wrong_verifier, 'S256');
        $this->assertFalse($result);
    }

    /**
     * Test PKCE validation with unsupported method
     */
    public function test_validate_pkce_unsupported_method(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        $challenge = PKCEValidator::generate_challenge($verifier, 'S256');
        
        $result = PKCEValidator::validate($challenge, $verifier, 'plain');
        $this->assertFalse($result);
    }

    /**
     * Test PKCE validation with verifier too short
     */
    public function test_validate_pkce_verifier_too_short(): void
    {
        $short_verifier = 'short'; // Less than 43 characters
        $challenge = 'some_challenge';
        
        $result = PKCEValidator::validate($challenge, $short_verifier, 'S256');
        $this->assertFalse($result);
    }

    /**
     * Test PKCE validation with verifier too long
     */
    public function test_validate_pkce_verifier_too_long(): void
    {
        $long_verifier = str_repeat('a', 129); // More than 128 characters
        $challenge = 'some_challenge';
        
        $result = PKCEValidator::validate($challenge, $long_verifier, 'S256');
        $this->assertFalse($result);
    }

    /**
     * Test PKCE validation with invalid verifier characters
     */
    public function test_validate_pkce_invalid_verifier_characters(): void
    {
        $invalid_verifier = 'test_verifier_with_invalid_chars_@#$%^&*()_plus_43chars';
        $challenge = 'some_challenge';
        
        $result = PKCEValidator::validate($challenge, $invalid_verifier, 'S256');
        $this->assertFalse($result);
    }

    /**
     * Test generating code challenge
     */
    public function test_generate_challenge(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        
        $challenge = PKCEValidator::generate_challenge($verifier, 'S256');
        
        $this->assertIsString($challenge);
        $this->assertGreaterThan(0, strlen($challenge));
        
        // Should be base64url encoded (no +, /, = characters)
        $this->assertStringNotContainsString('+', $challenge);
        $this->assertStringNotContainsString('/', $challenge);
        $this->assertStringNotContainsString('=', $challenge);
    }

    /**
     * Test generating code challenge with unsupported method
     */
    public function test_generate_challenge_unsupported_method(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        
        $challenge = PKCEValidator::generate_challenge($verifier, 'plain');
        
        $this->assertEquals('', $challenge);
    }

    /**
     * Test generating secure code verifier
     */
    public function test_generate_verifier(): void
    {
        $verifier1 = PKCEValidator::generate_verifier();
        $verifier2 = PKCEValidator::generate_verifier();
        
        $this->assertIsString($verifier1);
        $this->assertIsString($verifier2);
        
        // Should be at least 43 characters
        $this->assertGreaterThanOrEqual(43, strlen($verifier1));
        $this->assertGreaterThanOrEqual(43, strlen($verifier2));
        
        // Should be different each time (extremely unlikely to be the same)
        $this->assertNotEquals($verifier1, $verifier2);
        
        // Should only contain valid characters
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\-._~]+$/', $verifier1);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9\-._~]+$/', $verifier2);
    }

    /**
     * Test checking if method is supported
     */
    public function test_is_method_supported(): void
    {
        $this->assertTrue(PKCEValidator::is_method_supported('S256'));
        $this->assertFalse(PKCEValidator::is_method_supported('plain'));
        $this->assertFalse(PKCEValidator::is_method_supported('invalid'));
        $this->assertFalse(PKCEValidator::is_method_supported(''));
    }

    /**
     * Test getting supported methods
     */
    public function test_get_supported_methods(): void
    {
        $methods = PKCEValidator::get_supported_methods();
        
        $this->assertIsArray($methods);
        $this->assertContains('S256', $methods);
        $this->assertNotContains('plain', $methods);
    }

    /**
     * Test end-to-end PKCE flow
     */
    public function test_complete_pkce_flow(): void
    {
        // Generate verifier
        $verifier = PKCEValidator::generate_verifier();
        $this->assertIsString($verifier);
        
        // Generate challenge from verifier
        $challenge = PKCEValidator::generate_challenge($verifier, 'S256');
        $this->assertIsString($challenge);
        
        // Validate verifier against challenge
        $result = PKCEValidator::validate($challenge, $verifier, 'S256');
        $this->assertTrue($result);
        
        // Ensure wrong verifier fails
        $wrong_verifier = PKCEValidator::generate_verifier();
        $wrong_result = PKCEValidator::validate($challenge, $wrong_verifier, 'S256');
        $this->assertFalse($wrong_result);
    }

    /**
     * Test consistent challenge generation
     */
    public function test_consistent_challenge_generation(): void
    {
        $verifier = 'test_verifier_43_characters_minimum_length_abc123';
        
        $challenge1 = PKCEValidator::generate_challenge($verifier, 'S256');
        $challenge2 = PKCEValidator::generate_challenge($verifier, 'S256');
        
        // Same verifier should always produce same challenge
        $this->assertEquals($challenge1, $challenge2);
    }
}