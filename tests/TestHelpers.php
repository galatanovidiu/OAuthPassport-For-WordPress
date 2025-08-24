<?php
/**
 * Test Helper Functions
 * 
 * Shared utility functions for OAuth Passport tests.
 * 
 * @package OAuthPassport
 */

namespace OAuthPassport\Tests;

/**
 * Helper function for base64url encoding
 * 
 * @param string $data Data to encode
 * @return string Base64url encoded string
 */
function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Helper function for base64url decoding
 * 
 * @param string $data Data to decode
 * @return string Decoded string
 */
function base64url_decode(string $data): string {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}
