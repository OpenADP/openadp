// Package main provides a comprehensive test runner for the OpenADP Go project.
//
// This tool discovers and runs all tests in the OpenADP project:
// - Unit tests in pkg/
// - Integration tests (when available)
// - Benchmark tests
// - Coverage reporting
//
// Usage:
//
//	go run cmd/run-tests/main.go [options]
//	./build/run-tests [options]
//
// Options:
//
//	-unit-only         Run only unit tests
//	-bench-only        Run only benchmark tests
//	-integration-only  Run only integration tests (when available)
//	-verbose           Verbose output (-v flag to go test)
//	-coverage          Run with coverage reporting
//	-race              Run with race detection
//	-short             Run with -short flag (skip slow tests)
//	-parallel N        Set parallelism level
//	-timeout duration  Set test timeout (default: 10m)
//	-help              Show this help message
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const version = "1.0.0"

// TestRunner manages the execution of Go tests
type TestRunner struct {
	projectRoot string
	testResults map[string]bool
	startTime   time.Time
	verbose     bool
	coverage    bool
}

// NewTestRunner creates a new test runner instance
func NewTestRunner() *TestRunner {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("❌ Failed to get working directory: %v\n", err)
		os.Exit(1)
	}

	return &TestRunner{
		projectRoot: wd,
		testResults: make(map[string]bool),
		startTime:   time.Now(),
	}
}

// runCommand executes a command and returns true if successful
func (tr *TestRunner) runCommand(cmd []string, description string, cwd string) bool {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("🧪 %s\n", description)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Command: %s\n", strings.Join(cmd, " "))
	fmt.Printf("Working directory: %s\n", cwd)
	fmt.Println()

	execCmd := exec.Command(cmd[0], cmd[1:]...)
	execCmd.Dir = cwd
	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr

	err := execCmd.Run()
	success := err == nil

	tr.testResults[description] = success

	if success {
		fmt.Printf("✅ %s - PASSED\n", description)
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("❌ %s - FAILED (exit code: %d)\n", description, exitError.ExitCode())
		} else {
			fmt.Printf("❌ %s - ERROR: %v\n", description, err)
		}
	}

	return success
}

// runUnitTests runs all unit tests in pkg/
func (tr *TestRunner) runUnitTests(verbose, coverage, race, short bool, timeout string, parallel int) bool {
	cmd := []string{"go", "test"}

	if verbose {
		cmd = append(cmd, "-v")
	}
	if coverage {
		cmd = append(cmd, "-cover", "-coverprofile=coverage.out")
	}
	if race {
		cmd = append(cmd, "-race")
	}
	if short {
		cmd = append(cmd, "-short")
	}
	if timeout != "" {
		cmd = append(cmd, "-timeout", timeout)
	}
	if parallel > 0 {
		cmd = append(cmd, "-parallel", strconv.Itoa(parallel))
	}

	cmd = append(cmd, "./pkg/...")

	return tr.runCommand(cmd, "Unit Tests (pkg/...)", tr.projectRoot)
}

// runBenchmarkTests runs benchmark tests
func (tr *TestRunner) runBenchmarkTests(verbose bool, timeout string) bool {
	cmd := []string{"go", "test", "-bench=.", "-benchmem"}

	if verbose {
		cmd = append(cmd, "-v")
	}
	if timeout != "" {
		cmd = append(cmd, "-timeout", timeout)
	}

	cmd = append(cmd, "./pkg/...")

	return tr.runCommand(cmd, "Benchmark Tests (pkg/...)", tr.projectRoot)
}

// runIntegrationTests runs integration tests (when available)
func (tr *TestRunner) runIntegrationTests(verbose, short bool, timeout string) bool {
	// Check if integration tests exist
	integrationDir := filepath.Join(tr.projectRoot, "tests", "integration")
	if _, err := os.Stat(integrationDir); os.IsNotExist(err) {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("🧪 Integration Tests (tests/integration/)\n")
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		fmt.Println("No integration tests directory found")
		fmt.Println("✅ Integration Tests (tests/integration/) - PASSED (no tests)")
		tr.testResults["Integration Tests (tests/integration/)"] = true
		return true
	}

	cmd := []string{"go", "test"}

	if verbose {
		cmd = append(cmd, "-v")
	}
	if short {
		cmd = append(cmd, "-short")
	}
	if timeout != "" {
		cmd = append(cmd, "-timeout", timeout)
	}

	cmd = append(cmd, "./tests/integration/...")

	return tr.runCommand(cmd, "Integration Tests (tests/integration/)", tr.projectRoot)
}

// runCmdTests runs tests for command-line tools
func (tr *TestRunner) runCmdTests(verbose, race, short bool, timeout string) bool {
	cmd := []string{"go", "test"}

	if verbose {
		cmd = append(cmd, "-v")
	}
	if race {
		cmd = append(cmd, "-race")
	}
	if short {
		cmd = append(cmd, "-short")
	}
	if timeout != "" {
		cmd = append(cmd, "-timeout", timeout)
	}

	cmd = append(cmd, "./cmd/...")

	return tr.runCommand(cmd, "Command Tests (cmd/...)", tr.projectRoot)
}

// runAuthTests runs authentication tests
func (tr *TestRunner) runAuthTests(verbose, short bool, timeout string) bool {
	// Check if auth tests exist
	authDir := filepath.Join(tr.projectRoot, "tests", "auth")
	if _, err := os.Stat(authDir); os.IsNotExist(err) {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("🧪 Auth Tests (tests/auth/)\n")
		fmt.Printf("%s\n", strings.Repeat("=", 60))
		fmt.Println("No auth tests directory found")
		fmt.Println("✅ Auth Tests (tests/auth/) - PASSED (no tests)")
		tr.testResults["Auth Tests (tests/auth/)"] = true
		return true
	}

	cmd := []string{"go", "test"}

	if verbose {
		cmd = append(cmd, "-v")
	}
	if short {
		cmd = append(cmd, "-short")
	}
	if timeout != "" {
		cmd = append(cmd, "-timeout", timeout)
	}

	cmd = append(cmd, "./tests/auth/...")

	return tr.runCommand(cmd, "Auth Tests (tests/auth/)", tr.projectRoot)
}

// runBuildTests verifies that all packages build successfully
func (tr *TestRunner) runBuildTests() bool {
	cmd := []string{"go", "build", "./..."}
	return tr.runCommand(cmd, "Build Test (go build ./...)", tr.projectRoot)
}

// runVetTests runs go vet on all packages
func (tr *TestRunner) runVetTests() bool {
	cmd := []string{"go", "vet", "./..."}
	return tr.runCommand(cmd, "Vet Test (go vet ./...)", tr.projectRoot)
}

// runFormatTests checks if code is properly formatted
func (tr *TestRunner) runFormatTests() bool {
	cmd := []string{"gofmt", "-l", "."}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("🧪 Format Test (gofmt -l .)\n")
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Command: %s\n", strings.Join(cmd, " "))
	fmt.Printf("Working directory: %s\n", tr.projectRoot)
	fmt.Println()

	execCmd := exec.Command(cmd[0], cmd[1:]...)
	execCmd.Dir = tr.projectRoot
	output, err := execCmd.Output()

	success := err == nil && len(strings.TrimSpace(string(output))) == 0

	tr.testResults["Format Test (gofmt -l .)"] = success

	if success {
		fmt.Printf("✅ Format Test (gofmt -l .) - PASSED\n")
	} else {
		if len(strings.TrimSpace(string(output))) > 0 {
			fmt.Printf("❌ Format Test (gofmt -l .) - FAILED\n")
			fmt.Printf("Unformatted files:\n%s\n", string(output))
			fmt.Println("Run 'go fmt ./...' to fix formatting issues")
		} else {
			fmt.Printf("❌ Format Test (gofmt -l .) - ERROR: %v\n", err)
		}
	}

	return success
}

// generateCoverageReport generates and displays coverage report
func (tr *TestRunner) generateCoverageReport() {
	if _, err := os.Stat("coverage.out"); err == nil {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("📊 Coverage Report\n")
		fmt.Printf("%s\n", strings.Repeat("=", 60))

		// Generate HTML coverage report
		cmd := exec.Command("go", "tool", "cover", "-html=coverage.out", "-o", "coverage.html")
		cmd.Dir = tr.projectRoot
		if err := cmd.Run(); err == nil {
			fmt.Println("✅ HTML coverage report generated: coverage.html")
		}

		// Display coverage summary
		cmd = exec.Command("go", "tool", "cover", "-func=coverage.out")
		cmd.Dir = tr.projectRoot
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// checkDependencies verifies that required tools are available
func (tr *TestRunner) checkDependencies() bool {
	fmt.Println("🔍 Checking dependencies...")

	tools := []string{"go", "gofmt"}
	allAvailable := true

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			fmt.Printf("❌ %s not available\n", tool)
			allAvailable = false
		} else {
			fmt.Printf("✅ %s available\n", tool)
		}
	}

	return allAvailable
}

// printSummary prints the test results summary
func (tr *TestRunner) printSummary() bool {
	elapsed := time.Since(tr.startTime)

	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("🏁 TEST SUMMARY\n")
	fmt.Printf("%s\n", strings.Repeat("=", 80))

	totalTests := len(tr.testResults)
	passedTests := 0

	// Sort test names for consistent output
	var testNames []string
	for testName := range tr.testResults {
		testNames = append(testNames, testName)
	}
	sort.Strings(testNames)

	for _, testName := range testNames {
		result := tr.testResults[testName]
		if result {
			passedTests++
		}
		status := "✅ PASSED"
		if !result {
			status = "❌ FAILED"
		}
		fmt.Printf("%-12s %s\n", status, testName)
	}

	failedTests := totalTests - passedTests

	fmt.Printf("\n%s\n", strings.Repeat("=", 80))
	fmt.Printf("Total: %d test suites\n", totalTests)
	fmt.Printf("Passed: %d\n", passedTests)
	fmt.Printf("Failed: %d\n", failedTests)
	if totalTests > 0 {
		fmt.Printf("Success Rate: %.1f%%\n", float64(passedTests)/float64(totalTests)*100)
	}
	fmt.Printf("Elapsed Time: %.1fs\n", elapsed.Seconds())

	if failedTests == 0 {
		fmt.Printf("\n🎉 ALL TESTS PASSED! Project status: GREEN ✅\n")
		return true
	} else {
		fmt.Printf("\n💥 %d test suite(s) failed. Project status: RED ❌\n", failedTests)
		return false
	}
}

func printHelp() {
	fmt.Printf(`OpenADP Go Test Runner v%s

DESCRIPTION:
    Comprehensive test runner for the OpenADP Go implementation.
    Discovers and runs all tests, builds tools, and provides detailed reporting.

USAGE:
    run-tests [OPTIONS]

OPTIONS:
    --unit-only         Run only unit tests
    --integration-only  Run only integration tests
    --build-only        Only build tools
    --bench             Run benchmarks
    --lint              Run linting (requires golangci-lint)
    --coverage          Generate coverage reports
    --verbose           Verbose test output
    --help              Show this help message
    --version           Show version information

EXAMPLES:
    # Run all tests with coverage
    run-tests --coverage --verbose
    
    # Run only unit tests
    run-tests --unit-only
    
    # Build tools and run integration tests
    run-tests --build-only --integration-only
    
    # Run benchmarks
    run-tests --bench

REQUIREMENTS:
    - Go 1.19+ installed
    - golangci-lint (optional, for linting)

`, version)
}

func main() {
	var (
		unitOnly        = flag.Bool("unit-only", false, "Run only unit tests")
		integrationOnly = flag.Bool("integration-only", false, "Run only integration tests")
		buildOnly       = flag.Bool("build-only", false, "Only build tools")
		bench           = flag.Bool("bench", false, "Run benchmarks")
		lint            = flag.Bool("lint", false, "Run linting")
		coverage        = flag.Bool("coverage", false, "Generate coverage reports")
		verbose         = flag.Bool("verbose", false, "Verbose output")
		showVersion     = flag.Bool("version", false, "Show version")
		help            = flag.Bool("help", false, "Show help")
	)

	flag.Parse()

	if *help {
		printHelp()
		return
	}

	if *showVersion {
		fmt.Printf("OpenADP Go Test Runner v%s\n", version)
		return
	}

	runner := NewTestRunner()
	runner.verbose = *verbose
	runner.coverage = *coverage

	fmt.Println("🚀 OpenADP Go Test Runner")
	fmt.Printf("Project root: %s\n", runner.projectRoot)

	// Check dependencies
	if !runner.checkDependencies() {
		os.Exit(1)
	}

	success := true

	// Determine which tests to run
	runAll := !(*unitOnly || *integrationOnly || *buildOnly || *bench || *lint)

	// Build and format tests (unless specifically skipped or running specific test types)
	if runAll {
		if !*buildOnly {
			success = runner.runBuildTests() && success
			success = runner.runVetTests() && success
		}
		if !runner.runFormatTests() {
			success = false
		}
	}

	// Run selected test suites
	if runAll || *unitOnly {
		success = runner.runUnitTests(*verbose, *coverage, false, false, "", 0) && success
	}

	if runAll || *integrationOnly {
		success = runner.runIntegrationTests(*verbose, false, "") && success
	}

	// Run cmd tests (includes fuzz tests for server API)
	if runAll {
		success = runner.runCmdTests(*verbose, false, false, "") && success
	}

	// Run auth tests
	if runAll {
		success = runner.runAuthTests(*verbose, false, "") && success
	}

	if runAll || *bench {
		success = runner.runBenchmarkTests(*verbose, "") && success
	}

	if runAll || *lint {
		success = runner.runVetTests() && success
	}

	// Generate coverage report if coverage was enabled
	if *coverage {
		runner.generateCoverageReport()
	}

	// Print summary and exit
	overallSuccess := runner.printSummary()
	if overallSuccess {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
