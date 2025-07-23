# OAuth Passport Troubleshooting Guide

This guide helps diagnose and resolve common OAuth issues.

## Table of Contents
1. [Common Issues](#common-issues)
2. [Debugging Steps](#debugging-steps)
3. [Error Reference](#error-reference)
4. [Testing OAuth Flow](#testing-oauth-flow)
5. [Database Troubleshooting](#database-troubleshooting)
6. [Performance Issues](#performance-issues)

## Common Issues

### "Invalid client" Error

**Symptoms:**
- Getting "invalid_client" error during authorization or token exchange
- Client appears in database but authentication fails

**Solutions:**
1. Verify client_id matches exactly (case-sensitive)
2. Check client_secret for confidential clients
3. Ensure client exists in `wp_oauth_passport_clients` table
4. For dynamic clients, verify registration was successful

**Debug queries:**
```sql
SELECT * FROM wp_oauth_passport_clients WHERE client_id = 'your_client_id';
```

### OAuth Not Working at All

**Symptoms:**
- 404 errors on OAuth endpoints
- Discovery endpoints not accessible

**Solutions:**
1. Check plugin is activated
2. Ensure pretty permalinks are enabled
3. Flush rewrite rules: Settings > Permalinks > Save
4. Verify .htaccess has proper rules
5. Check REST API is working: `/wp-json/`

### Endpoints Return 404

**Solutions:**
- Ensure OAuth Passport plugin is active
- Permalinks are enabled (not "Plain")
- REST API is accessible
- Check endpoint URLs:
  - Authorization: `https://your-site.com/wp-json/oauth-passport/v1/authorize`
  - Token: `https://your-site.com/wp-json/oauth-passport/v1/token`
  - Registration: `https://your-site.com/wp-json/oauth-passport/v1/register`
  - JWKS: `https://your-site.com/wp-json/oauth-passport/v1/jwks`

### "Invalid grant" Error

**Symptoms:**
- Error during token exchange
- Authorization code rejected

**Common causes:**
1. **Code expired** - Codes expire in 5 minutes
2. **Code already used** - Codes are single-use
3. **PKCE mismatch** - Verifier doesn't match challenge
4. **Redirect URI mismatch** - Must match exactly

**Solutions:**
```php
// Check code in database
SELECT * FROM wp_oauth_passport_tokens 
WHERE token_type = 'code' 
AND token_value = 'your_code';
```

### Token Not Working

**Symptoms:**
- 401 Unauthorized with valid token
- "Invalid token" errors

**Solutions:**
1. Check token hasn't expired:
```sql
SELECT * FROM wp_oauth_passport_tokens 
WHERE token_value = 'your_token' 
AND expires_at > NOW();
```

2. Verify Authorization header format:
```
Authorization: Bearer YOUR_TOKEN_HERE
```

3. Ensure OAuth is enabled in admin

4. Check if token has required scopes

### Discovery Not Working

**Symptoms:**
- `.well-known` URLs return 404
- Clients can't auto-configure

**Solutions:**
1. Test URLs directly:
```bash
curl https://your-site.com/.well-known/oauth-authorization-server
curl https://your-site.com/.well-known/oauth-protected-resource
```

2. Check rewrite rules are active
3. Verify no conflicting plugins
4. Check web server configuration

## Debugging Steps

### 1. Enable Debug Logging

In `wp-config.php`:
```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
```

### 2. Check Database Tables

```sql
SHOW TABLES LIKE '%oauth_passport%';
```
Should show: `wp_oauth_passport_tokens`, `wp_oauth_passport_clients`, `wp_oauth_passport_logs`

### 3. Verify Admin Interface
- Visit Settings > OAuth Passport in admin
- Check if OAuth is enabled
- Review token lifetimes

### 4. Test Basic Flow

```bash
# 1. Register client
curl -X POST https://your-site.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'

# 2. Get client info (with registration token)
curl -X GET https://your-site.com/wp-json/oauth-passport/v1/register/{client_id} \
  -H "Authorization: Bearer {registration_token}"
```

## Error Reference

### OAuth Errors (RFC 6749)

| Error | Description | Common Causes |
|-------|-------------|---------------|
| `invalid_request` | Request is malformed | Missing required parameters |
| `invalid_client` | Client authentication failed | Wrong credentials, client doesn't exist |
| `invalid_grant` | Authorization grant invalid | Expired code, wrong verifier |
| `unauthorized_client` | Client not authorized | Client can't use this grant type |
| `unsupported_grant_type` | Grant type not supported | Only authorization_code and refresh_token supported |
| `invalid_scope` | Requested scope invalid | Scope doesn't exist or unauthorized |

### HTTP Status Codes

- `400 Bad Request` - Malformed request
- `401 Unauthorized` - Authentication required/failed
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Endpoint doesn't exist
- `500 Internal Server Error` - Server error (check logs)

## Testing OAuth Flow

### Complete Flow Test

```bash
# 1. Generate PKCE challenge
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c 1-43)
code_challenge=$(echo -n $code_verifier | openssl dgst -sha256 -binary | openssl base64 -A | tr -d "=" | tr '/+' '_-')

# 2. Build authorization URL
echo "https://your-site.com/wp-json/oauth-passport/v1/authorize?client_id={client_id}&redirect_uri={redirect_uri}&code_challenge=$code_challenge&code_challenge_method=S256"

# 3. Exchange code for token
curl -X POST https://your-site.com/wp-json/oauth-passport/v1/token \
  -H "Content-Type: application/json" \
  -d "{
    \"grant_type\": \"authorization_code\",
    \"code\": \"{auth_code}\",
    \"client_id\": \"{client_id}\",
    \"client_secret\": \"{client_secret}\",
    \"code_verifier\": \"$code_verifier\"
  }"

# 4. Refresh token
curl -X POST https://your-site.com/wp-json/oauth-passport/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "refresh_token",
    "refresh_token": "{refresh_token}",
    "client_id": "{client_id}",
    "client_secret": "{client_secret}"
  }'
```

### Test Endpoints

```bash
# Discovery
curl https://your-site.com/.well-known/oauth-authorization-server

# JWKS
curl https://your-site.com/wp-json/oauth-passport/v1/jwks

# Protected resource (with token)
curl -H "Authorization: Bearer {access_token}" \
  https://your-site.com/wp-json/wp/v2/users/me
```

## Database Troubleshooting

### Check Tables Structure

```sql
DESCRIBE wp_oauth_passport_tokens;
DESCRIBE wp_oauth_passport_clients;
DESCRIBE wp_oauth_passport_logs;
```

### Common Queries

```bash
# Active tokens
SELECT * FROM wp_oauth_passport_tokens
WHERE expires_at > NOW();

# Client list
SELECT * FROM wp_oauth_passport_clients;

# Recent errors
SELECT * FROM wp_oauth_passport_logs
WHERE level = 'error'
ORDER BY created_at DESC
LIMIT 20;
```

### Cleanup Old Data

```sql
# Remove expired tokens (done automatically daily)
DELETE FROM wp_oauth_passport_tokens WHERE expires_at < NOW();

# Clear old logs
DELETE FROM wp_oauth_passport_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

## Performance Issues

### Slow Token Validation

1. Check token table size: `SELECT COUNT(*) FROM wp_oauth_passport_tokens;`
2. Ensure indexes exist
3. Run cleanup to remove expired tokens
4. Consider shorter token lifetimes

### Check Indexes

```sql
SHOW INDEX FROM wp_oauth_passport_tokens;
SHOW INDEX FROM wp_oauth_passport_clients;
SHOW INDEX FROM wp_oauth_passport_logs;
```

### Add Missing Indexes

```sql
-- If missing
ALTER TABLE wp_oauth_passport_tokens ADD INDEX idx_token_lookup (token_type, token_value, expires_at);
ALTER TABLE wp_oauth_passport_tokens ADD INDEX idx_cleanup (expires_at);
ALTER TABLE wp_oauth_passport_clients ADD INDEX idx_client_id (client_id);
```

## Getting Help

1. Check error logs: `wp-content/debug.log`
2. Review OAuth event logs in admin
3. Enable debug mode for detailed errors
4. Check browser console for JavaScript errors
5. Verify server requirements (PHP 8.0+, MySQL 5.7+) 