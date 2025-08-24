# OAuth Passport Test Suite

This directory contains a comprehensive test suite for the OAuth Passport WordPress plugin, providing thorough coverage of all OAuth 2.1 functionality, security features, and edge cases.

## Test Structure

```
tests/
├── Unit/                           # Unit tests for individual components
│   ├── OAuth2ServerTest.php        # Main OAuth server functionality
│   ├── SecurityTest.php            # Security and cryptographic functions
│   ├── ClientRepositoryTest.php    # Client data management
│   ├── TokenRepositoryTest.php     # Token storage and retrieval
│   ├── AuthorizationServiceTest.php # Authorization flow logic
│   ├── TokenServiceTest.php        # Token generation and validation
│   ├── PKCEValidatorTest.php       # PKCE implementation
│   └── ScopeManagerTest.php        # OAuth scope management
├── Integration/                    # End-to-end integration tests
│   └── OAuthFlowTest.php          # Complete OAuth flows
├── bootstrap.php                   # Test environment setup
├── bootstrap-wp-env.php           # wp-env specific bootstrap
└── README.md                      # This file
```

## Test Coverage

### Core OAuth Functionality
- ✅ **OAuth2Server**: Complete server functionality, endpoint registration, error handling
- ✅ **Authorization Flow**: Authorization code generation, validation, PKCE support
- ✅ **Token Management**: Access tokens, refresh tokens, token introspection
- ✅ **Client Management**: Client registration, validation, credential verification
- ✅ **Scope Management**: Scope validation, filtering, user permissions

### Security Features
- ✅ **Cryptographic Security**: Token generation, hashing, entropy validation
- ✅ **Timing Attack Resistance**: Constant-time comparisons, secure validation
- ✅ **Input Validation**: Parameter sanitization, malformed input handling
- ✅ **Memory Safety**: Sensitive data handling, error message security
- ✅ **PKCE Implementation**: S256 and plain methods, challenge validation

### Integration Tests
- ✅ **Complete OAuth Flows**: Authorization code flow, refresh token flow
- ✅ **Client Registration**: Dynamic client registration (RFC 7591)
- ✅ **Token Revocation**: Individual and bulk token revocation
- ✅ **Error Scenarios**: Invalid clients, expired tokens, malformed requests
- ✅ **Concurrent Operations**: Race conditions, token reuse prevention

### Edge Cases and Error Handling
- ✅ **Boundary Conditions**: Minimum/maximum values, edge cases
- ✅ **Database Errors**: Connection failures, transaction handling
- ✅ **Performance Testing**: Large datasets, concurrent operations
- ✅ **Configuration Validation**: Security settings, environment checks

## Running Tests

### Prerequisites

1. **PHP 8.1+** with required extensions (openssl, etc.)
2. **Composer** for dependency management
3. **WordPress Test Library** or **wp-env** for WordPress integration
4. **MySQL/MariaDB** for database tests (if not using wp-env)

### Quick Start

```bash
# Install dependencies
composer install

# Run all tests
./bin/run-tests.sh

# Run with coverage
./bin/run-tests.sh --coverage

# Run specific test suite
./bin/run-tests.sh --testsuite unit
./bin/run-tests.sh --testsuite integration
./bin/run-tests.sh --testsuite security

# Run specific test
./bin/run-tests.sh --filter OAuth2ServerTest
```

### Using wp-env

```bash
# Start wp-env
wp-env start

# Run tests in wp-env
./bin/run-tests.sh --wp-env --coverage
```

### Manual PHPUnit

```bash
# Standard WordPress test environment
vendor/bin/phpunit --configuration phpunit.xml.dist

# wp-env environment
vendor/bin/phpunit --configuration phpunit-wp-env.xml

# With coverage
vendor/bin/phpunit --coverage-html coverage
```

## Test Configuration

### Environment Variables

- `WP_TESTS_DIR`: WordPress test library directory
- `WP_CORE_DIR`: WordPress core directory
- `WP_TEST_DB_NAME`: Test database name
- `WP_TEST_DB_USER`: Test database user
- `WP_TEST_DB_PASSWORD`: Test database password
- `WP_TEST_DB_HOST`: Test database host

### Test-Specific Settings

The test bootstrap automatically configures:
- Shorter token lifetimes for faster testing
- Disabled rate limiting
- Lower hash costs for performance
- Enabled debug logging
- Blocked external HTTP requests

## Test Data Management

### Automatic Cleanup
- Test data is automatically cleaned up after each test run
- Database tables are reset between test suites
- Temporary files and options are removed

### Manual Cleanup
```bash
# Clean up test data
./bin/run-tests.sh --no-cleanup  # Skip automatic cleanup
```

## Writing New Tests

### Unit Test Example

```php
<?php
namespace OAuthPassport\Tests\Unit;

use OAuthPassport\YourClass;
use WP_UnitTestCase;

class YourClassTest extends WP_UnitTestCase
{
    private YourClass $instance;

    public function setUp(): void
    {
        parent::setUp();
        $this->instance = new YourClass();
    }

    public function test_your_method(): void
    {
        $result = $this->instance->yourMethod();
        $this->assertTrue($result);
    }

    public function tearDown(): void
    {
        parent::tearDown();
        // Clean up test data
    }
}
```

### Integration Test Example

```php
<?php
namespace OAuthPassport\Tests\Integration;

use WP_UnitTestCase;
use WP_REST_Request;

class YourIntegrationTest extends WP_UnitTestCase
{
    public function test_complete_flow(): void
    {
        // Set up test data
        $client = $this->createTestClient();
        
        // Test the flow
        $request = new WP_REST_Request('POST', '/oauth/v2/token');
        $response = rest_do_request($request);
        
        $this->assertEquals(200, $response->get_status());
    }
}
```

## Test Guidelines

### Best Practices
1. **Isolation**: Each test should be independent and not rely on other tests
2. **Cleanup**: Always clean up test data in `tearDown()` methods
3. **Assertions**: Use specific assertions with descriptive messages
4. **Coverage**: Aim for high code coverage but focus on meaningful tests
5. **Performance**: Keep tests fast by using minimal data and mocking when appropriate

### Security Testing
1. **Input Validation**: Test with malformed, oversized, and malicious input
2. **Timing Attacks**: Verify constant-time operations
3. **Cryptographic Quality**: Test randomness and entropy
4. **Error Handling**: Ensure no sensitive data leaks in error messages

### Naming Conventions
- Test classes: `ClassNameTest.php`
- Test methods: `test_method_description()`
- Test data: Use descriptive prefixes like `test_client_`, `test_token_`

## Continuous Integration

The test suite is designed to work with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run Tests
  run: |
    composer install
    ./bin/run-tests.sh --coverage
    
- name: Upload Coverage
  uses: codecov/codecov-action@v1
  with:
    file: ./coverage/clover.xml
```

## Troubleshooting

### Common Issues

1. **WordPress Test Library Not Found**
   ```bash
   # Install using WP-CLI
   wp scaffold plugin-tests oauth-passport
   ```

2. **Database Connection Errors**
   ```bash
   # Check database credentials
   mysql -u root -p -e "SHOW DATABASES;"
   ```

3. **Memory Limit Issues**
   ```bash
   # Increase PHP memory limit
   php -d memory_limit=512M vendor/bin/phpunit
   ```

4. **Permission Errors**
   ```bash
   # Fix file permissions
   chmod +x bin/run-tests.sh
   ```

### Debug Mode

Enable verbose output for debugging:
```bash
./bin/run-tests.sh --verbose --stop-on-failure
```

## Contributing

When adding new features to OAuth Passport:

1. **Write Tests First**: Follow TDD principles
2. **Update Existing Tests**: Ensure compatibility
3. **Add Integration Tests**: Test complete workflows
4. **Security Review**: Include security-focused tests
5. **Documentation**: Update test documentation

## Performance Benchmarks

The test suite includes performance benchmarks:
- Token generation: < 1 second for 100 tokens
- Hash verification: < 2 seconds for 10 verifications
- Database operations: < 100ms per operation
- Complete OAuth flow: < 500ms end-to-end

## Security Compliance

Tests verify compliance with:
- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: PKCE (Proof Key for Code Exchange)
- **RFC 7591**: Dynamic Client Registration
- **RFC 8414**: Authorization Server Metadata
- **OAuth 2.1**: Latest security best practices

## Test Metrics

Current test coverage (as of last update):
- **Lines**: 95%+ coverage target
- **Functions**: 100% coverage target
- **Classes**: 100% coverage target
- **Security Tests**: 100+ security-specific test cases
- **Integration Tests**: 20+ end-to-end scenarios

---

For more information about OAuth Passport, see the main [README.md](../README.md) file.
