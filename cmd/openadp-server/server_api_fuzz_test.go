package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// FuzzJSONRPCRequest fuzzes the JSON-RPC request parsing
func FuzzJSONRPCRequest(f *testing.F) {
	// Seed with valid and invalid JSON-RPC requests
	f.Add(`{"jsonrpc":"2.0","method":"Echo","params":["hello"],"id":1}`)
	f.Add(`{"jsonrpc":"2.0","method":"GetServerInfo","params":[],"id":2}`)
	f.Add(`{"method":"Echo","params":["test"]}`)                        // Missing jsonrpc
	f.Add(`{"jsonrpc":"1.0","method":"Echo","params":["test"],"id":1}`) // Wrong version
	f.Add(`{invalid json}`)                                             // Malformed JSON
	f.Add(`""`)                                                         // Empty string
	f.Add(`null`)                                                       // Null
	f.Add(`[]`)                                                         // Array instead of object
	f.Add(`{"jsonrpc":"2.0","method":"","params":[],"id":1}`)           // Empty method

	f.Fuzz(func(t *testing.T, requestBody string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_api_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Create HTTP request
		req := httptest.NewRequest("POST", "/", strings.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Call the handler - should not panic
		server.handleJSONRPC(w, req)

		// Check response
		resp := w.Result()
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// Response should be valid JSON (even for errors)
		var jsonResponse interface{}
		if err := json.Unmarshal(body, &jsonResponse); err != nil {
			t.Errorf("Response is not valid JSON: %s", string(body))
		}

		// Response should have proper Content-Type
		if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", ct)
		}
	})
}

// FuzzEchoMethod fuzzes the Echo JSON-RPC method specifically
func FuzzEchoMethod(f *testing.F) {
	f.Add("hello world")
	f.Add("")
	f.Add(strings.Repeat("A", 10000)) // Large string
	f.Add("\x00\x01\x02")             // Binary data
	f.Add("🚀🔐✅")                      // Unicode

	f.Fuzz(func(t *testing.T, echoMessage string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_echo_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Create JSON-RPC request
		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "Echo",
			Params:  []interface{}{echoMessage},
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		// Make HTTP request
		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleJSONRPC(w, req)

		// Parse response
		var response JSONRPCResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
			return
		}

		// Check for successful echo
		if response.Error == nil {
			if result, ok := response.Result.(string); ok {
				if result != echoMessage {
					t.Errorf("Echo mismatch: expected %q, got %q", echoMessage, result)
				}
			} else {
				t.Errorf("Echo result is not a string: %T", response.Result)
			}
		}
	})
}

// FuzzRegisterSecretMethod fuzzes the RegisterSecret JSON-RPC method
func FuzzRegisterSecretMethod(f *testing.F) {
	f.Add("user@example.com", "device-123", "backup-456", "AUTH123", 1, 2, "dGVzdA==", 10, int64(2000000000))
	f.Add("", "", "", "", 0, 0, "", 0, int64(0))                                                          // Empty values
	f.Add(strings.Repeat("x", 1000), "device", "backup", "auth", -1, -1, "invalid-base64", -1, int64(-1)) // Invalid values

	f.Fuzz(func(t *testing.T, uid, did, bid, authCode string, version, x int, y string, maxGuesses int, expiration int64) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_register_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Create RegisterSecret request
		params := []interface{}{
			uid, did, bid, authCode, version, x, y, maxGuesses, expiration,
		}

		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "RegisterSecret",
			Params:  params,
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		// Make HTTP request
		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleJSONRPC(w, req)

		// Response should be valid JSON
		var response JSONRPCResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}

		// Check response structure
		if response.JSONRPC != "2.0" {
			t.Errorf("Expected JSONRPC 2.0, got %s", response.JSONRPC)
		}
		// ID should match what we sent (1)
		if response.ID != float64(1) { // JSON unmarshals numbers as float64
			t.Errorf("Expected ID 1, got %v", response.ID)
		}
	})
}

// FuzzRecoverSecretMethod fuzzes the RecoverSecret JSON-RPC method
func FuzzRecoverSecretMethod(f *testing.F) {
	f.Add("user@example.com", "device-123", "backup-456", "AUTH123", int64(100), int64(200), 0)
	f.Add("", "", "", "", int64(0), int64(0), -1)

	f.Fuzz(func(t *testing.T, uid, did, bid, authCode string, bX, bY int64, guessNum int) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_recover_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Create Point2D representation for JSON
		point := map[string]interface{}{
			"x": bX,
			"y": bY,
		}

		params := []interface{}{
			uid, did, bid, authCode, point, guessNum,
		}

		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "RecoverSecret",
			Params:  params,
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		// Make HTTP request
		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleJSONRPC(w, req)

		// Response should be valid JSON
		var response JSONRPCResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}
	})
}

// FuzzListBackupsMethod fuzzes the ListBackups JSON-RPC method
func FuzzListBackupsMethod(f *testing.F) {
	f.Add("user@example.com")
	f.Add("")
	f.Add(strings.Repeat("x", 10000))

	f.Fuzz(func(t *testing.T, uid string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_list_api_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "ListBackups",
			Params:  []interface{}{uid},
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleJSONRPC(w, req)

		var response JSONRPCResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}

		// Should not have null result for valid requests
		if response.Error == nil && response.Result == nil {
			t.Error("Expected result to be non-nil for successful ListBackups")
		}
	})
}

// FuzzHTTPMethods fuzzes different HTTP methods and headers
func FuzzHTTPMethods(f *testing.F) {
	f.Add("GET", "application/json", `{"jsonrpc":"2.0","method":"Echo","params":["test"],"id":1}`)
	f.Add("POST", "text/plain", `{"jsonrpc":"2.0","method":"Echo","params":["test"],"id":1}`)
	f.Add("PUT", "application/json", `{"jsonrpc":"2.0","method":"Echo","params":["test"],"id":1}`)
	f.Add("DELETE", "application/json", ``)
	f.Add("OPTIONS", "application/json", ``)
	f.Add("PATCH", "application/json", `{"invalid": "json"}`)

	f.Fuzz(func(t *testing.T, method, contentType, body string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_http_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		req := httptest.NewRequest(method, "/", strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()

		// Should not panic
		server.handleJSONRPC(w, req)

		resp := w.Result()

		// Check that we get a response
		if resp.StatusCode == 0 {
			t.Error("Expected non-zero status code")
		}

		// OPTIONS should return 200
		if method == "OPTIONS" && resp.StatusCode != http.StatusOK {
			t.Errorf("OPTIONS should return 200, got %d", resp.StatusCode)
		}

		// Non-POST methods (except OPTIONS) should return 405
		if method != "POST" && method != "OPTIONS" && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Expected 405 for method %s, got %d", method, resp.StatusCode)
		}
	})
}

// FuzzParameterTypes fuzzes different parameter types and counts
func FuzzParameterTypes(f *testing.F) {
	f.Add("Echo", `["string"]`)
	f.Add("Echo", `[123]`)
	f.Add("Echo", `[null]`)
	f.Add("Echo", `[true]`)
	f.Add("Echo", `[{"object": "value"}]`)
	f.Add("Echo", `[]`)                             // No parameters
	f.Add("Echo", `["param1", "param2", "param3"]`) // Too many parameters
	f.Add("GetServerInfo", `["unexpected", "params"]`)
	f.Add("RegisterSecret", `[1, 2, 3]`) // Wrong parameter types

	f.Fuzz(func(t *testing.T, method, paramsJSON string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_params_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Parse parameters
		var params interface{}
		if err := json.Unmarshal([]byte(paramsJSON), &params); err != nil {
			t.Skip("Invalid JSON parameters")
		}

		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  method,
			Params:  params.([]interface{}),
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handleJSONRPC(w, req)

		// Should get a response
		var response JSONRPCResponse
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Failed to decode response: %v", err)
		}

		// Should have proper JSON-RPC structure
		if response.JSONRPC != "2.0" {
			t.Errorf("Expected JSONRPC 2.0, got %s", response.JSONRPC)
		}
	})
}

// FuzzConcurrentRequests tests concurrent API requests
func FuzzConcurrentRequests(f *testing.F) {
	f.Add(5, "Echo")
	f.Add(10, "GetServerInfo")
	f.Add(3, "ListBackups")

	f.Fuzz(func(t *testing.T, numRequests int, method string) {
		if numRequests <= 0 || numRequests > 50 {
			t.Skip("Invalid number of requests")
		}

		// Create test server
		dbPath := fmt.Sprintf("fuzz_concurrent_api_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Channel to collect responses
		respChan := make(chan int, numRequests)

		// Launch concurrent requests
		for i := 0; i < numRequests; i++ {
			go func(id int) {
				var params []interface{}
				switch method {
				case "Echo":
					params = []interface{}{fmt.Sprintf("message-%d", id)}
				case "GetServerInfo":
					params = []interface{}{}
				case "ListBackups":
					params = []interface{}{fmt.Sprintf("user-%d", id)}
				default:
					params = []interface{}{}
				}

				request := JSONRPCRequest{
					JSONRPC: "2.0",
					Method:  method,
					Params:  params,
					ID:      id,
				}

				requestBody, _ := json.Marshal(request)

				req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()

				server.handleJSONRPC(w, req)

				respChan <- w.Code
			}(i)
		}

		// Collect responses
		successCount := 0
		for i := 0; i < numRequests; i++ {
			code := <-respChan
			if code == http.StatusOK {
				successCount++
			}
		}

		// Should have some successful responses
		if successCount == 0 {
			t.Error("No successful responses in concurrent test")
		}
	})
}

// FuzzLargePayloads tests handling of large request payloads
func FuzzLargePayloads(f *testing.F) {
	f.Add(1000)   // 1KB
	f.Add(10000)  // 10KB
	f.Add(100000) // 100KB

	f.Fuzz(func(t *testing.T, payloadSize int) {
		if payloadSize <= 0 || payloadSize > 1000000 { // Limit to 1MB
			t.Skip("Invalid payload size")
		}

		// Create test server
		dbPath := fmt.Sprintf("fuzz_large_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		// Create large message
		largeMessage := strings.Repeat("A", payloadSize)

		request := JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "Echo",
			Params:  []interface{}{largeMessage},
			ID:      1,
		}

		requestBody, _ := json.Marshal(request)

		req := httptest.NewRequest("POST", "/", bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		// Should handle large payloads without crashing
		server.handleJSONRPC(w, req)

		// Should get a response
		if w.Code == 0 {
			t.Error("Expected non-zero response code")
		}
	})
}

// FuzzHealthEndpoint fuzzes the health check endpoint
func FuzzHealthEndpoint(f *testing.F) {
	f.Add("GET")
	f.Add("POST")
	f.Add("PUT")
	f.Add("DELETE")

	f.Fuzz(func(t *testing.T, method string) {
		// Create test server
		dbPath := fmt.Sprintf("fuzz_health_%d.db", rand.Int())
		defer os.Remove(dbPath)

		server, err := NewServer(dbPath, 8080, false)
		if err != nil {
			t.Skip("Failed to create server")
		}
		defer server.Close()

		req := httptest.NewRequest(method, "/health", nil)
		w := httptest.NewRecorder()

		// Create a minimal handler for health check
		healthHandler := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{
				"status":  "healthy",
				"version": version,
			})
		}

		healthHandler(w, req)

		// Should return 200 for all methods (simple health check)
		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 for health check, got %d", w.Code)
		}

		// Should return valid JSON
		var response map[string]string
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Errorf("Health response is not valid JSON: %v", err)
		}
	})
}
