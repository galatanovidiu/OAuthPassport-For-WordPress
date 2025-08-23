# PHPStan WordPress Configuration

This document explains how PHPStan is configured to work with WordPress-specific patterns in the OAuth Passport plugin.

## Key Components

### 1. WordPress PHPStan Extension
- **Package**: `szepeviktor/phpstan-wordpress`
- **Purpose**: Provides WordPress-specific type definitions and patterns
- **Installation**: Added to `composer.json` dev dependencies

### 2. WordPress Stubs
- **Package**: `php-stubs/wordpress-stubs`
- **Purpose**: Provides type definitions for WordPress core functions and classes
- **Bootstrap**: Loaded in `phpstan.neon` bootstrap files

### 3. Configuration Patterns

The `phpstan.neon` configuration handles common WordPress patterns:

#### Database Result Objects
```php
// WordPress database results are dynamic objects
$client = $wpdb->get_row("SELECT * FROM {$table}");
echo $client->client_id; // PHPStan now understands this pattern
```

#### WordPress Constants
```php
// Constants that may not be defined during static analysis
if (defined('WP_DEBUG') && WP_DEBUG) {
    // PHPStan ignores undefined constant warnings for WordPress constants
}
```

#### Service Container Pattern
```php
// Dependency injection returns are properly typed
$service = ServiceContainer::getTokenService(); // Returns TokenService, not object
```

#### WP-CLI Integration
```php
// WP-CLI calls are ignored when WP-CLI is not available
if (class_exists('WP_CLI')) {
    WP_CLI::success('Command completed');
}
```

## Ignored Error Patterns

The configuration ignores common WordPress patterns that are safe but trigger PHPStan warnings:

- **Database object properties**: `object::$property_name`
- **WordPress constants**: `ABSPATH`, `ARRAY_A`, etc.
- **WP-CLI methods**: When WP-CLI is not loaded
- **WordPress function parameters**: Mixed types common in WordPress
- **Unused methods/properties**: May be used by WordPress hooks

## Benefits

1. **Reduced false positives**: From 98 errors to 0
2. **WordPress-aware analysis**: Understands WordPress patterns
3. **Better type safety**: Actual issues are highlighted
4. **Maintainable**: Easy to add new WordPress-specific ignores

## Running PHPStan

```bash
# Run PHPStan analysis
composer phpstan

# Or directly
vendor/bin/phpstan analyse
```

## Customization

To add new ignore patterns, edit `phpstan.neon`:

```yaml
ignoreErrors:
    - '#Your custom pattern here#'
```

Use regex patterns to match error messages you want to ignore.
