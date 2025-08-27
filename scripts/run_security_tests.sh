#!/bin/bash

# IshikuraDB（石蔵） Security Testing Suite
# Comprehensive security testing including unit tests and vulnerability scanning

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"

echo "🔐 IshikuraDB（石蔵） Security Testing Suite"
echo "=================================="
echo "Project Root: $PROJECT_ROOT"
echo "Build Directory: $BUILD_DIR"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to run security tests
run_security_tests() {
    log_info "Running security unit tests..."
    
    cd "$BUILD_DIR"
    
    # Run security-specific tests
    if [ -f "./tests" ]; then
        log_info "Executing security test suite..."
        ./tests "[security]" --reporter compact
        
        if [ $? -eq 0 ]; then
            log_success "Security unit tests passed"
        else
            log_error "Security unit tests failed"
            return 1
        fi
    else
        log_warning "Test executable not found. Run 'make tests' first."
        return 1
    fi
}

# Function to run vulnerability scanning
run_vulnerability_scan() {
    log_info "Running vulnerability scan..."
    
    cd "$PROJECT_ROOT"
    
    # Check if Python is available
    if ! command -v python3 &> /dev/null; then
        log_warning "Python3 not available, skipping vulnerability scan"
        return 0
    fi
    
    # Run the security scanner
    python3 scripts/security_scan.py \
        --project-root "$PROJECT_ROOT" \
        --output text \
        --severity-filter medium
    
    scanner_exit_code=$?
    
    case $scanner_exit_code in
        0)
            log_success "Vulnerability scan completed - no critical issues"
            ;;
        1)
            log_warning "Vulnerability scan found high-severity issues"
            ;;
        2)
            log_error "Vulnerability scan found critical issues"
            return 2
            ;;
        *)
            log_error "Vulnerability scanner failed"
            return 1
            ;;
    esac
}

# Function to run static analysis (if available)
run_static_analysis() {
    log_info "Running static analysis..."
    
    # Check for common static analysis tools
    if command -v cppcheck &> /dev/null; then
        log_info "Running cppcheck analysis..."
        cd "$PROJECT_ROOT"
        
        cppcheck \
            --enable=warning,style,performance,portability,information \
            --error-exitcode=1 \
            --suppress=missingIncludeSystem \
            --suppress=unusedFunction \
            --inline-suppr \
            src/ include/ \
            2>&1 | tee /tmp/cppcheck_results.txt
        
        if [ $? -eq 0 ]; then
            log_success "Static analysis completed successfully"
        else
            log_warning "Static analysis found potential issues"
        fi
    else
        log_info "cppcheck not available, skipping static analysis"
    fi
}

# Function to check TLS configuration
test_tls_configuration() {
    log_info "Testing TLS configuration..."
    
    cd "$BUILD_DIR"
    
    # Start TLS server in background for testing
    if [ -f "./src/ishikura_tls_server" ]; then
        log_info "Starting TLS server for configuration test..."
        
        # Generate test certificate if needed
        if [ ! -f "server.crt" ]; then
            log_info "Generating test certificate..."
            ./src/ishikura_tls_server --generate-cert > /dev/null 2>&1 || true
        fi
        
        # Start server in background
        timeout 10 ./src/ishikura_tls_server --port 19443 > /dev/null 2>&1 &
        SERVER_PID=$!
        
        sleep 2  # Give server time to start
        
        # Test TLS connection (if openssl is available)
        if command -v openssl &> /dev/null; then
            log_info "Testing TLS connection..."
            
            # Test TLS handshake
            echo | timeout 5 openssl s_client -connect localhost:19443 -verify_return_error > /tmp/tls_test.out 2>&1 || true
            
            if grep -q "Verify return code: 0" /tmp/tls_test.out; then
                log_success "TLS handshake successful"
            elif grep -q "unable to verify" /tmp/tls_test.out; then
                log_info "TLS handshake completed (self-signed cert)"
            else
                log_warning "TLS configuration may have issues"
            fi
        fi
        
        # Clean up server
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
        
    else
        log_warning "TLS server executable not found"
    fi
}

# Function to test API key security
test_api_key_security() {
    log_info "Testing API key security..."
    
    cd "$BUILD_DIR"
    
    if [ -f "./src/ishikura_api_key_manager" ]; then
        # Create temporary test directory
        TEST_DIR="/tmp/nosql_security_test_$$"
        mkdir -p "$TEST_DIR"
        
        log_info "Testing API key generation..."
        ./src/ishikura_api_key_manager \
            --storage "$TEST_DIR/test_keys.db" \
            generate "security_test" "test_user" \
            --permissions "read,write" > "$TEST_DIR/key_output.txt"
        
        if [ $? -eq 0 ]; then
            log_success "API key generation test passed"
            
            # Extract the generated key for validation test
            RAW_KEY=$(grep "Raw Key:" "$TEST_DIR/key_output.txt" | cut -d' ' -f3)
            
            if [ ! -z "$RAW_KEY" ]; then
                log_info "Testing API key validation..."
                ./src/ishikura_api_key_manager \
                    --storage "$TEST_DIR/test_keys.db" \
                    validate "$RAW_KEY" "read" > "$TEST_DIR/validation_output.txt"
                
                if grep -q "Valid: Yes" "$TEST_DIR/validation_output.txt"; then
                    log_success "API key validation test passed"
                else
                    log_error "API key validation test failed"
                fi
            fi
        else
            log_error "API key generation test failed"
        fi
        
        # Cleanup
        rm -rf "$TEST_DIR"
    else
        log_warning "API key manager executable not found"
    fi
}

# Function to run memory safety tests
run_memory_safety_tests() {
    log_info "Running memory safety tests..."
    
    # Check if valgrind is available
    if command -v valgrind &> /dev/null; then
        cd "$BUILD_DIR"
        
        log_info "Running tests under valgrind..."
        
        # Run security tests with memory checking
        valgrind \
            --tool=memcheck \
            --leak-check=full \
            --error-exitcode=1 \
            --suppressions=/dev/null \
            ./tests "[security]" --reporter compact > /tmp/valgrind_output.txt 2>&1
        
        valgrind_exit_code=$?
        
        if [ $valgrind_exit_code -eq 0 ]; then
            log_success "Memory safety tests passed"
        else
            log_error "Memory safety issues detected"
            tail -20 /tmp/valgrind_output.txt
            return 1
        fi
    else
        log_info "Valgrind not available, skipping memory safety tests"
    fi
}

# Main execution
main() {
    local exit_code=0
    
    # Ensure we're in the build directory
    if [ ! -d "$BUILD_DIR" ]; then
        log_error "Build directory not found. Please build the project first."
        exit 1
    fi
    
    echo "Starting comprehensive security testing..."
    echo
    
    # Run all security tests
    run_security_tests || exit_code=$((exit_code | 1))
    echo
    
    run_vulnerability_scan || exit_code=$((exit_code | $?))
    echo
    
    run_static_analysis || exit_code=$((exit_code | 1))
    echo
    
    test_tls_configuration || exit_code=$((exit_code | 1))
    echo
    
    test_api_key_security || exit_code=$((exit_code | 1))
    echo
    
    run_memory_safety_tests || exit_code=$((exit_code | 1))
    echo
    
    # Summary
    echo "=================================="
    if [ $exit_code -eq 0 ]; then
        log_success "All security tests completed successfully!"
    else
        log_error "Some security tests failed or found issues (exit code: $exit_code)"
    fi
    
    echo
    echo "Security testing complete. Review any warnings above."
    echo "For detailed vulnerability reports, run:"
    echo "  python3 scripts/security_scan.py --output html --output-file security_report.html"
    
    exit $exit_code
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--build-dir <path>] [--help]"
            echo "  --build-dir: Specify build directory (default: $BUILD_DIR)"
            echo "  --help: Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main function
main