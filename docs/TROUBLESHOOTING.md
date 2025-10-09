# OAuth Passport Troubleshooting

Quick solutions for common OAuth issues.

## Quick Diagnostics

### Check Plugin Status
1. Plugin is activated: `Plugins > Installed Plugins`
2. OAuth is enabled: `Settings > OAuth Passport`
3. Pretty permalinks: `Settings > Permalinks` (not "Plain")
4. REST API works: Visit `https://yoursite.com/wp-json/`

### Test Basic Endpoints
```bash
# Discovery endpoints
curl https://yoursite.com/.well-known/oauth-authorization-server
curl https://yoursite.com/.well-known/oauth-protected-resource

# Admin endpoints (requires authentication)
curl https://yoursite.com/wp-json/oauth-passport/v1/admin/endpoints
```

## Common Errors

### "Invalid Client" Error

**Cause:** Client authentication failed

**Solutions:**
1. Verify `client_id` matches exactly (case-sensitive)
2. Check `client_secret` for confidential clients
3. Confirm client exists in database:
```sql
SELECT * FROM wp_oauth_passport_clients WHERE client_id = 'your_client_id';
```

### "Invalid Grant" Error

**Cause:** Authorization code or refresh token is invalid

**Common Issues:**
- Authorization code expired (5 minutes)
- Code already used (single-use only)
- PKCE verifier doesn't match challenge
- Redirect URI doesn't match exactly

**Check code status:**
```sql
SELECT * FROM wp_oauth_passport_tokens 
WHERE token_type = 'code' AND token_value = 'your_code';
```

### 404 Errors on OAuth Endpoints

**Solutions:**
1. Flush permalinks: `Settings > Permalinks > Save Changes`
2. Check `.htaccess` file exists and is writable
3. Verify REST API: `https://yoursite.com/wp-json/`
4. Ensure plugin is activated

### Token Not Working (401 Unauthorized)

**Check These:**
1. Token hasn't expired:
```sql
SELECT * FROM wp_oauth_passport_tokens 
WHERE token_value = 'your_token' AND expires_at > NOW();
```

2. Correct Authorization header format:
```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

3. OAuth is enabled in admin panel

### Discovery Endpoints Not Working

**Test URLs:**
```bash
curl https://yoursite.com/.well-known/oauth-authorization-server
curl https://yoursite.com/.well-known/oauth-protected-resource
```

**Solutions:**
1. Check rewrite rules are active
2. Verify no conflicting plugins
3. Test with different HTTP client

## Debug Mode

Enable WordPress debugging in `wp-config.php`:
```php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
```

Check logs at: `wp-content/debug.log`

## Database Issues

### Check Required Tables
```sql
SHOW TABLES LIKE '%oauth_passport%';
```
Should show: `wp_oauth_passport_tokens`, `wp_oauth_passport_clients`

### Recreate Tables
If tables are missing, deactivate and reactivate the plugin.

### Performance Issues
Clean up expired tokens:
```sql
DELETE FROM wp_oauth_passport_tokens WHERE expires_at < NOW();
```

## Testing Complete Flow

### 1. Register Test Client
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Test Client",
    "redirect_uris": ["http://localhost:3000/callback"]
  }'
```

### 2. Generate PKCE Values
```bash
code_verifier=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-43)
code_challenge=$(echo -n $code_verifier | openssl dgst -sha256 -binary | base64 | tr -d "=" | tr '/+' '_-')
echo "Verifier: $code_verifier"
echo "Challenge: $code_challenge"
```

### 3. Build Authorization URL
```
https://yoursite.com/wp-json/oauth-passport/v1/authorize?
  client_id=YOUR_CLIENT_ID&
  redirect_uri=http://localhost:3000/callback&
  code_challenge=YOUR_CHALLENGE&
  code_challenge_method=S256&
  response_type=code&
  scope=read
```

### 4. Exchange Code for Token
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTH_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "code_verifier=$code_verifier"
```

### 5. Test API Access
```bash
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  https://yoursite.com/wp-json/wp/v2/users/me
```

## Error Reference

| Error | Meaning | Common Fixes |
|-------|---------|--------------|
| `invalid_request` | Missing required parameters | Check request format |
| `invalid_client` | Client authentication failed | Verify client credentials |
| `invalid_grant` | Authorization grant invalid | Check code/token validity |
| `invalid_scope` | Requested scope not allowed | Review available scopes |
| `unsupported_grant_type` | Grant type not supported | Use `authorization_code` or `refresh_token` |

## Getting Help

1. **Check error logs:** WordPress debug log and OAuth event logs in admin
2. **Review database:** Verify tokens and clients exist
3. **Test endpoints:** Use curl to test each endpoint individually
4. **Check requirements:** PHP 8.0+, MySQL 5.7+, HTTPS (production)
5. **Browser console:** Look for JavaScript errors in admin interface

## Useful Database Queries

```sql
-- View all clients
SELECT client_id, client_name, created_at FROM wp_oauth_passport_clients;

-- Active tokens
SELECT token_type, client_id, user_id, scope, expires_at 
FROM wp_oauth_passport_tokens 
WHERE expires_at > NOW();

-- Token count by type
SELECT token_type, COUNT(*) as count 
FROM wp_oauth_passport_tokens 
GROUP BY token_type;

-- Expired tokens
SELECT COUNT(*) as expired_tokens
FROM wp_oauth_passport_tokens 
WHERE expires_at < NOW();

-- Token cleanup (remove expired)
DELETE FROM wp_oauth_passport_tokens WHERE expires_at < NOW();
```