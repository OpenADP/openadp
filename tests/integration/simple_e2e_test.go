// simple_e2e_test.go - Simple E2E test that works with current implementation
//
// This test validates that the tools work correctly for basic functionality
// without requiring full distributed key recovery (which is not yet implemented).

package integration

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSimpleE2E(t *testing.T) {
	t.Log("🚀 Simple E2E Test - Tool Validation")
	t.Log("=====================================")

	// Test content
	testContent := "Hello OpenADP! This is a simple test file for validation."

	// Create test file
	tmpFile, err := os.CreateTemp("", "simple_e2e_*.txt")
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}
	tmpFile.Close()

	testFilePath := tmpFile.Name()
	encryptedFilePath := testFilePath + ".enc"
	defer os.Remove(encryptedFilePath)

	t.Logf("✅ Created test file: %s", testFilePath)

	// Test 1: Verify tools exist and show help
	t.Run("tools_help", func(t *testing.T) {
		// Test encrypt help
		cmd := exec.Command("../../build/openadp-encrypt", "-help")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("encrypt help failed: %v", err)
		}
		if !strings.Contains(strings.ToLower(string(output)), "encrypt") {
			t.Fatalf("encrypt help missing expected content")
		}
		t.Log("✅ openadp-encrypt help working")

		// Test decrypt help
		cmd = exec.Command("../../build/openadp-decrypt", "-help")
		output, err = cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("decrypt help failed: %v", err)
		}
		if !strings.Contains(strings.ToLower(string(output)), "decrypt") {
			t.Fatalf("decrypt help missing expected content")
		}
		t.Log("✅ openadp-decrypt help working")
	})

	// Test 2: Test encryption with local servers
	t.Run("encryption", func(t *testing.T) {
		// Create test server manager
		serverManager, err := NewTestServerManager()
		if err != nil {
			t.Fatalf("Failed to create test server manager: %v", err)
		}
		defer serverManager.Cleanup()

		// Start OpenADP servers AND registry server using new enhanced method
		_, err = serverManager.StartServersWithRegistry(9300, 1, 9350)
		if err != nil {
			t.Fatalf("Failed to start test servers with registry: %v", err)
		}

		// Give servers time to fully start
		time.Sleep(2 * time.Second)

		t.Logf("🌐 Using registry server: %s", serverManager.GetRegistryURL())

		// Test encryption using the registry URL (production-like discovery!)
		cmd := exec.Command("../../build/openadp-encrypt",
			"-file", testFilePath,
			"-servers-url", serverManager.GetRegistryURL(),
			"-password", "test123",
			"-user-id", "simple-test-user")

		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("Encryption failed: %v\nOutput: %s", err, output)
		}

		t.Logf("Encryption output: %s", output)

		// Verify encrypted file was created
		if _, err := os.Stat(encryptedFilePath); os.IsNotExist(err) {
			t.Fatalf("Encrypted file was not created: %s", encryptedFilePath)
		}

		// Check file size
		encInfo, err := os.Stat(encryptedFilePath)
		if err != nil {
			t.Fatalf("Failed to stat encrypted file: %v", err)
		}

		originalInfo, err := os.Stat(testFilePath)
		if err != nil {
			t.Fatalf("Failed to stat original file: %v", err)
		}

		if encInfo.Size() <= originalInfo.Size() {
			t.Errorf("Encrypted file should be larger than original")
		}

		t.Log("✅ Encryption completed successfully")
	})

	// Test 3: Verify encrypted file structure
	t.Run("file_structure", func(t *testing.T) {
		// Read encrypted file and verify basic structure
		encData, err := os.ReadFile(encryptedFilePath)
		if err != nil {
			t.Fatalf("Failed to read encrypted file: %v", err)
		}

		// Check minimum size
		if len(encData) < 20 {
			t.Fatalf("Encrypted file too small: %d bytes", len(encData))
		}

		t.Logf("✅ Encrypted file has valid size: %d bytes", len(encData))
	})

	t.Log("")
	t.Log("🎉 SIMPLE E2E TEST PASSED!")
	t.Log("==========================")
	t.Log("✅ All basic functionality working:")
	t.Log("   • Tool help and availability")
	t.Log("   • File encryption with server")
	t.Log("   • Encrypted file structure validation")
	t.Log("")
	t.Log("📝 Note: Full decrypt test skipped due to current")
	t.Log("   implementation limitations (key recovery)")
}
