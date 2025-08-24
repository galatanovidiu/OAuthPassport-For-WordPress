#!/bin/bash

# OAuth Passport Test Runner
# Comprehensive test execution script with various options

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
COVERAGE=false
VERBOSE=false
FILTER=""
TESTSUITE=""
STOP_ON_FAILURE=false
PARALLEL=false
CLEANUP=true
WP_ENV=false

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --coverage          Generate code coverage report"
    echo "  -v, --verbose           Verbose output"
    echo "  -f, --filter PATTERN    Run only tests matching pattern"
    echo "  -s, --testsuite SUITE   Run specific test suite (unit|integration|security)"
    echo "  --stop-on-failure       Stop on first failure"
    echo "  --parallel              Run tests in parallel (if supported)"
    echo "  --no-cleanup            Don't clean up test data after run"
    echo "  --wp-env                Use wp-env for testing"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Run all tests"
    echo "  $0 -c                                # Run tests with coverage"
    echo "  $0 -s unit                           # Run only unit tests"
    echo "  $0 -f OAuth2ServerTest               # Run only OAuth2Server tests"
    echo "  $0 --wp-env -c                       # Run with wp-env and coverage"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--filter)
            FILTER="$2"
            shift 2
            ;;
        -s|--testsuite)
            TESTSUITE="$2"
            shift 2
            ;;
        --stop-on-failure)
            STOP_ON_FAILURE=true
            shift
            ;;
        --parallel)
            PARALLEL=true
            shift
            ;;
        --no-cleanup)
            CLEANUP=false
            shift
            ;;
        --wp-env)
            WP_ENV=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}OAuth Passport Test Runner${NC}"
echo "=========================="

# Check if we're in the right directory
if [[ ! -f "$PROJECT_DIR/composer.json" ]]; then
    echo -e "${RED}Error: Not in OAuth Passport project directory${NC}"
    exit 1
fi

# Change to project directory
cd "$PROJECT_DIR"

# Check dependencies
echo -e "${YELLOW}Checking dependencies...${NC}"

if [[ ! -d "vendor" ]]; then
    echo -e "${YELLOW}Installing Composer dependencies...${NC}"
    composer install --no-interaction --prefer-dist
fi

# Set up environment variables
export WP_TESTS_DIR="${WP_TESTS_DIR:-/tmp/wordpress-tests-lib}"
export WP_CORE_DIR="${WP_CORE_DIR:-/tmp/wordpress/}"

# Check WordPress test environment
if [[ "$WP_ENV" == "false" ]] && [[ ! -d "$WP_TESTS_DIR" ]]; then
    echo -e "${YELLOW}WordPress test library not found. Setting up...${NC}"
    
    # Download WordPress test library
    if command -v wp &> /dev/null; then
        wp scaffold plugin-tests oauth-passport --dir="$PROJECT_DIR"
    else
        echo -e "${RED}WP-CLI not found. Please install WordPress test library manually or use --wp-env${NC}"
        echo "See: https://make.wordpress.org/cli/handbook/plugin-unit-tests/"
        exit 1
    fi
fi

# Build PHPUnit command
PHPUNIT_CMD="vendor/bin/phpunit"

# Add configuration file
if [[ "$WP_ENV" == "true" ]]; then
    PHPUNIT_CMD="$PHPUNIT_CMD --configuration phpunit-wp-env.xml"
else
    PHPUNIT_CMD="$PHPUNIT_CMD --configuration phpunit.xml.dist"
fi

# Add coverage option
if [[ "$COVERAGE" == "true" ]]; then
    PHPUNIT_CMD="$PHPUNIT_CMD --coverage-html coverage --coverage-text"
    echo -e "${YELLOW}Coverage reporting enabled${NC}"
fi

# Add verbose option
if [[ "$VERBOSE" == "true" ]]; then
    PHPUNIT_CMD="$PHPUNIT_CMD --verbose"
fi

# Add filter option
if [[ -n "$FILTER" ]]; then
    PHPUNIT_CMD="$PHPUNIT_CMD --filter '$FILTER'"
    echo -e "${YELLOW}Running tests matching: $FILTER${NC}"
fi

# Add test suite option
if [[ -n "$TESTSUITE" ]]; then
    case $TESTSUITE in
        unit)
            PHPUNIT_CMD="$PHPUNIT_CMD tests/Unit"
            echo -e "${YELLOW}Running unit tests only${NC}"
            ;;
        integration)
            PHPUNIT_CMD="$PHPUNIT_CMD tests/Integration"
            echo -e "${YELLOW}Running integration tests only${NC}"
            ;;
        security)
            PHPUNIT_CMD="$PHPUNIT_CMD --filter SecurityTest"
            echo -e "${YELLOW}Running security tests only${NC}"
            ;;
        *)
            echo -e "${RED}Unknown test suite: $TESTSUITE${NC}"
            echo "Available suites: unit, integration, security"
            exit 1
            ;;
    esac
fi

# Add stop on failure option
if [[ "$STOP_ON_FAILURE" == "true" ]]; then
    PHPUNIT_CMD="$PHPUNIT_CMD --stop-on-failure"
fi

# Add parallel option (if supported)
if [[ "$PARALLEL" == "true" ]]; then
    if command -v parallel &> /dev/null; then
        echo -e "${YELLOW}Parallel execution enabled${NC}"
        # This would require more complex setup for parallel PHPUnit execution
    else
        echo -e "${YELLOW}GNU parallel not found, running sequentially${NC}"
    fi
fi

# Pre-test setup
echo -e "${YELLOW}Setting up test environment...${NC}"

# Create coverage directory if needed
if [[ "$COVERAGE" == "true" ]]; then
    mkdir -p coverage
fi

# Set up database for tests (if not using wp-env)
if [[ "$WP_ENV" == "false" ]]; then
    # Check if MySQL is available
    if command -v mysql &> /dev/null; then
        echo -e "${YELLOW}Setting up test database...${NC}"
        mysql -u root -e "CREATE DATABASE IF NOT EXISTS oauth_passport_test;" 2>/dev/null || true
    fi
fi

# Run the tests
echo -e "${GREEN}Running tests...${NC}"
echo "Command: $PHPUNIT_CMD"
echo ""

# Execute tests with proper error handling
if [[ "$WP_ENV" == "true" ]]; then
    # Use wp-env to run tests
    wp-env run tests-wordpress bash -c "cd /var/www/html/wp-content/plugins/OAuthPassport && $PHPUNIT_CMD"
    TEST_EXIT_CODE=$?
else
    # Run tests directly
    eval $PHPUNIT_CMD
    TEST_EXIT_CODE=$?
fi

# Post-test cleanup
if [[ "$CLEANUP" == "true" ]]; then
    echo -e "${YELLOW}Cleaning up test data...${NC}"
    
    if [[ "$WP_ENV" == "false" ]] && command -v mysql &> /dev/null; then
        mysql -u root -e "DROP DATABASE IF EXISTS oauth_passport_test;" 2>/dev/null || true
    fi
fi

# Display results
echo ""
echo "=========================="
if [[ $TEST_EXIT_CODE -eq 0 ]]; then
    echo -e "${GREEN}✓ All tests passed!${NC}"
    
    if [[ "$COVERAGE" == "true" ]]; then
        echo -e "${BLUE}Coverage report generated in: coverage/index.html${NC}"
    fi
else
    echo -e "${RED}✗ Some tests failed!${NC}"
    echo -e "${RED}Exit code: $TEST_EXIT_CODE${NC}"
fi

# Additional information
echo ""
echo "Test Summary:"
echo "============="
echo "Configuration: $([ "$WP_ENV" == "true" ] && echo "wp-env" || echo "local")"
echo "Coverage: $([ "$COVERAGE" == "true" ] && echo "enabled" || echo "disabled")"
echo "Filter: ${FILTER:-"none"}"
echo "Test Suite: ${TESTSUITE:-"all"}"
echo "Cleanup: $([ "$CLEANUP" == "true" ] && echo "enabled" || echo "disabled")"

# Exit with the same code as PHPUnit
exit $TEST_EXIT_CODE
