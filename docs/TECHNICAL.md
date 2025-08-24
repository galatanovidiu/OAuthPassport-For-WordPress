# OAuth 2.1 Server Documentation

This documentation covers the core OAuth 2.1 server implementation for WordPress.

## Overview

OAuth Passport transforms your WordPress site into a secure OAuth 2.1 authorization server, allowing third-party applications to authenticate users and access WordPress resources.

## Quick Start

### 1. Client Registration

Register a new OAuth client via API:

```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.com/callback"]
  }'
```

Response includes `client_id`, `client_secret`, and `registration_access_token`.

### 2. Authorization Flow

1. **Authorization Request:**
```
https://yoursite.com/wp-json/oauth-passport/v1/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=YOUR_REDIRECT_URI&
  code_challenge=YOUR_PKCE_CHALLENGE&
  code_challenge_method=S256&
  response_type=code&
  scope=read
```

2. **Token Exchange:**
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=YOUR_PKCE_VERIFIER"
```

3. **API Access:**
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://yoursite.com/wp-json/wp/v2/posts
```

## API Endpoints

### OAuth Endpoints
- `POST /wp-json/oauth-passport/v1/register` - Client registration
- `GET/POST /wp-json/oauth-passport/v1/authorize` - Authorization
- `POST /wp-json/oauth-passport/v1/token` - Token exchange/refresh
- `GET /wp-json/oauth-passport/v1/jwks` - JSON Web Key Set

### Discovery Endpoints
- `GET /.well-known/oauth-authorization-server` - Server metadata (RFC 8414)
- `GET /.well-known/oauth-protected-resource` - Resource metadata (RFC 9728)

### Admin Endpoints
- `GET /wp-json/oauth-passport/v1/admin/clients` - List clients
- `GET /wp-json/oauth-passport/v1/admin/tokens` - List tokens
- `DELETE /wp-json/oauth-passport/v1/admin/tokens/{id}` - Revoke token

## OAuth Scopes

Default scopes:
- **read** - Access to read content and user profile
- **write** - Create and edit posts, pages, and media
- **admin** - Manage site settings and users

Add custom scopes:
```php
add_filter('oauth_passport_scopes', function($scopes) {
    $scopes['custom'] = 'Custom permission';
    return $scopes;
});
```

## Client Management

### Dynamic Registration (RFC 7591)

After registration, manage clients with the registration access token:

**Get client info:**
```bash
GET /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

**Update client:**
```bash
PUT /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
Content-Type: application/json

{
  "client_name": "Updated Name",
  "redirect_uris": ["https://new-callback.com"]
}
```

**Delete client:**
```bash
DELETE /wp-json/oauth-passport/v1/register/{client_id}
Authorization: Bearer {registration_access_token}
```

## WordPress Integration

### Admin Interface

Access OAuth management at **Settings > OAuth Passport**:
- Configure token lifetimes and security settings
- View and manage registered clients
- Monitor active tokens and revoke access
- View OAuth event logs

### Helper Functions

Check current OAuth token:
```php
$token = oauth_passport_get_current_token();
if ($token) {
    $scopes = explode(' ', $token->scope);
    $client_id = $token->client_id;
}
```

Check user permissions:
```php
if (oauth_passport_user_can('read')) {
    // User has read access
}

if (oauth_passport_user_has_scope('write')) {
    // OAuth token has write scope
}
```

### Protect Custom Endpoints

```php
add_action('rest_api_init', function() {
    register_rest_route('myapp/v1', '/data', [
        'methods' => 'GET',
        'callback' => 'my_endpoint',
        'permission_callback' => function() {
            return oauth_passport_user_can('read');
        }
    ]);
});
```

## Configuration

### Settings Filters

```php
// Enable/disable OAuth
add_filter('oauth_passport_enabled', '__return_true');

// Token lifetime (seconds)
add_filter('oauth_passport_access_token_lifetime', function() {
    return 3600; // 1 hour
});

add_filter('oauth_passport_refresh_token_lifetime', function() {
    return 2592000; // 30 days
});

// Allow localhost redirects (development only)
add_filter('oauth_passport_allow_localhost', '__return_true');
```

### Available Filters
- `oauth_passport_enabled` - Enable/disable functionality
- `oauth_passport_scopes` - Add custom scopes
- `oauth_passport_access_token_lifetime` - Access token expiration
- `oauth_passport_refresh_token_lifetime` - Refresh token expiration
- `oauth_passport_allow_localhost` - Allow localhost redirects

## Database Schema

### Tables Created
- `wp_oauth_passport_tokens` - Stores all token types (access, refresh, authorization codes)
- `wp_oauth_passport_clients` - Registered OAuth clients
- `wp_oauth_passport_logs` - OAuth events and errors

### Token Types
- `code` - Authorization codes (5 minutes)
- `access` - Access tokens (1 hour default)
- `refresh` - Refresh tokens (30 days default)
- `registration` - Registration access tokens (no expiration)

## Security Features

- **PKCE Required** - All authorization flows require PKCE with S256
- **Token Rotation** - Refresh tokens rotate on each use
- **Secure Storage** - All secrets are properly hashed
- **HTTPS Enforcement** - Required in production
- **Rate Limiting** - Protection against brute force attacks
- **Event Logging** - Comprehensive audit trail

## Standards Compliance

- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE)
- RFC 7591 (Dynamic Client Registration)
- RFC 7592 (Client Configuration)
- RFC 8414 (Authorization Server Metadata)
- RFC 9728 (Protected Resource Metadata)
- OAuth 2.1 Draft Specification

## Testing

Test the complete OAuth flow:

```bash
# 1. Register client
CLIENT_RESPONSE=$(curl -s -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{"client_name": "Test", "redirect_uris": ["http://localhost:3000"]}')

CLIENT_ID=$(echo $CLIENT_RESPONSE | jq -r '.client_id')
CLIENT_SECRET=$(echo $CLIENT_RESPONSE | jq -r '.client_secret')

# 2. Generate PKCE challenge
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
CODE_CHALLENGE=$(echo -n $CODE_VERIFIER | openssl dgst -sha256 -binary | base64 | tr -d "=" | tr '/+' '_-')

# 3. Visit authorization URL (manual step)
echo "Visit: https://yoursite.com/wp-json/oauth-passport/v1/authorize?client_id=$CLIENT_ID&redirect_uri=http://localhost:3000&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&response_type=code"

# 4. Exchange code for token (after getting code from redirect)
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" \
  -d "code_verifier=$CODE_VERIFIER"
```

For troubleshooting common issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).