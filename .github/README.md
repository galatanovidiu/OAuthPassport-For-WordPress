# GitHub Workflows

This directory contains GitHub Actions workflows for automated testing and releases.

## Workflows

### `test.yml` - Continuous Integration
**Triggers:** Push to main/develop branches, Pull requests
**Purpose:** Run automated tests and code quality checks

**What it does:**
- Tests against multiple PHP versions (8.0-8.3) and WordPress versions (6.4-latest)
- Runs PHPStan static analysis
- Runs PHPCS code style checks
- Runs PHPUnit tests
- Lints JavaScript and CSS
- Checks code formatting

### `release.yml` - Automated Releases
**Triggers:** Push tags matching `v*` (e.g., `v1.0.0`)
**Purpose:** Create GitHub releases with production-ready plugin zip

**What it does:**
- Installs production dependencies only (`composer install --no-dev`)
- Builds optimized JavaScript/CSS assets
- Creates plugin zip with only necessary files
- Creates GitHub release with changelog
- Uploads plugin zip as release asset

## Creating a Release

1. **Update version** in `oauth-passport.php` and `readme.txt`
2. **Commit changes** to main branch
3. **Create and push a tag:**
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
4. **GitHub Actions will automatically:**
   - Build the production plugin zip
   - Create a GitHub release
   - Upload the zip file as an asset

## Plugin Zip Contents

The automated build process creates a clean plugin zip containing only:

### ✅ Included Files
- `oauth-passport.php` - Main plugin file
- `readme.txt` - WordPress plugin directory metadata
- `includes/` - All PHP source files
- `build/` - Compiled JavaScript and CSS assets
- `docs/` - Documentation
- `vendor/composer/` - Composer autoloader (production only)

### ❌ Excluded Files
- `src/` - JavaScript source files (compiled to `build/`)
- `node_modules/` - Node.js dependencies
- `tests/` - PHPUnit tests
- `_notes/` - Development notes
- `examples/` - Example code
- `.github/` - GitHub workflows
- Development config files (`phpcs.xml.dist`, `phpstan.neon`, etc.)
- IDE and OS files (`.vscode/`, `.DS_Store`, etc.)

## File Size Optimization

The production build:
- Removes all development dependencies via `composer install --no-dev`
- Excludes 38+ development packages (PHPUnit, PHPStan, PHPCS, etc.)
- Minifies JavaScript assets
- Results in ~53 files, ~326KB total size

## Manual Testing

Test the build process locally:

```bash
# Full production build
npm run plugin-zip:build

# Check zip contents
unzip -l oauth-passport.zip

# Verify no development files
unzip -l oauth-passport.zip | grep -E "(test|phpunit|phpstan|node_modules)"
```

## Troubleshooting

**Build fails:** Check that all dependencies are properly installed:
```bash
npm ci
composer install
```

**Wrong files in zip:** Check `.distignore` file and `package.json` files array

**GitHub Actions failing:** Check the Actions tab on GitHub for detailed error logs