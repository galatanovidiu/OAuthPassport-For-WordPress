# OAuth Passport

[![WordPress Plugin Version](https://img.shields.io/badge/WordPress-6.4%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-8.0%2B-purple.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Transform your WordPress site into a secure OAuth 2.1 authorization server.

## What is OAuth Passport?

OAuth Passport enables your WordPress site to act as an OAuth provider, allowing third-party applications to authenticate users and access your APIs through secure, standards-compliant OAuth flows.

Perfect for:
- **Mobile Apps** - Secure authentication for iOS/Android apps
- **Desktop Applications** - OAuth integration for desktop software  
- **API Access** - Controlled access to WordPress REST API
- **Third-party Integrations** - Allow external services to connect
- **Single Sign-On** - Use WordPress as identity provider

## Key Features

✅ **OAuth 2.1 Compliant** - Full implementation with mandatory PKCE  
✅ **Dynamic Client Registration** - Self-service client registration (RFC 7591)  
✅ **Discovery Endpoints** - Automatic configuration discovery  
✅ **WordPress Integration** - Seamless user system integration  
✅ **Admin Interface** - React-based management panel  
✅ **Secure by Default** - HTTPS enforcement, token rotation, rate limiting

## Quick Start

### Installation
1. Upload plugin to `/wp-content/plugins/oauth-passport`
2. Activate through WordPress admin
3. Configure at **Settings > OAuth Passport**

### Register Your First Client
```bash
curl -X POST https://yoursite.com/wp-json/oauth-passport/v1/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My App",
    "redirect_uris": ["https://myapp.com/callback"]
  }'
```

### Authorization Flow
1. Direct users to authorization URL with PKCE
2. Exchange authorization code for access token
3. Use Bearer token for API access

## Documentation

📖 **[Complete Documentation](docs/README.md)** - Full setup and usage guide  
🔧 **[Technical Reference](docs/TECHNICAL.md)** - API endpoints and integration  
🚨 **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Requirements

- WordPress 6.4+
- PHP 8.0+
- MySQL 5.7+ / MariaDB 10.3+
- HTTPS (required in production)
- Pretty permalinks enabled

## Standards Compliance

- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE)
- RFC 7591 (Dynamic Client Registration)
- RFC 8414 (Authorization Server Metadata)
- OAuth 2.1 Draft Specification

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- 📚 **Documentation**: [docs/](docs/) folder
- 🐛 **Issues**: Report on GitHub

---

**Made with ❤️ for the WordPress community**
