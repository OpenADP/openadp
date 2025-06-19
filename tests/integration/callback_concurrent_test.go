package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// CallbackHandler handles HTTP callback requests
type CallbackHandler struct {
	received bool
	mu       sync.Mutex
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	fmt.Printf("✅ Callback received: %s\n", r.URL.Path)
	h.received = true

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Success"))
}

func (h *CallbackHandler) isReceived() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.received
}

func TestCallbackConcurrent(t *testing.T) {
	fmt.Println("🔄 Testing concurrent callback server and client...")

	// Create handler
	handler := &CallbackHandler{}

	// Create server
	server := &http.Server{
		Addr:    ":8889",
		Handler: handler,
	}

	// Channel to coordinate server shutdown
	serverDone := make(chan struct{})

	// Start server in goroutine
	go func() {
		defer close(serverDone)
		fmt.Println("🚀 Callback server started on http://localhost:8889")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}

		fmt.Println("🔒 Callback server stopped")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Start client request in goroutine
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)

		// Wait a bit for server to be ready
		time.Sleep(100 * time.Millisecond)

		fmt.Println("📡 Sending HTTP request...")

		// Make HTTP request
		resp, err := http.Get("http://localhost:8889/callback?code=test123&state=test")
		if err != nil {
			t.Errorf("HTTP request failed: %v", err)
			return
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Failed to read response body: %v", err)
			return
		}

		fmt.Printf("📊 HTTP result: status=%d\n", resp.StatusCode)
		fmt.Printf("📄 Response: %s\n", string(body))

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		if string(body) != "Success" {
			t.Errorf("Expected 'Success', got '%s'", string(body))
		}
	}()

	// Wait for request to complete or timeout
	select {
	case <-clientDone:
		// Client completed
	case <-time.After(5 * time.Second):
		t.Error("Client request timed out")
	}

	// Check if callback was received
	if !handler.isReceived() {
		t.Error("Callback was not received")
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Server shutdown error: %v", err)
	}

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server stopped
	case <-time.After(6 * time.Second):
		t.Error("Server shutdown timed out")
	}

	fmt.Println("✅ Concurrent test complete")
}

func TestCallbackMultipleConcurrent(t *testing.T) {
	fmt.Println("🔄 Testing multiple concurrent callback requests...")

	// Create handler
	handler := &CallbackHandler{}

	// Create server
	server := &http.Server{
		Addr:    ":8890", // Different port to avoid conflicts
		Handler: handler,
	}

	// Channel to coordinate server shutdown
	serverDone := make(chan struct{})

	// Start server in goroutine
	go func() {
		defer close(serverDone)
		fmt.Println("🚀 Callback server started on http://localhost:8890")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("Server error: %v", err)
		}

		fmt.Println("🔒 Callback server stopped")
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Number of concurrent requests
	numRequests := 5
	var wg sync.WaitGroup
	results := make(chan bool, numRequests)

	// Launch multiple concurrent requests
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(requestID int) {
			defer wg.Done()

			// Stagger requests slightly
			time.Sleep(time.Duration(requestID*10) * time.Millisecond)

			url := fmt.Sprintf("http://localhost:8890/callback?code=test%d&state=test%d", requestID, requestID)
			resp, err := http.Get(url)
			if err != nil {
				t.Errorf("Request %d failed: %v", requestID, err)
				results <- false
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Request %d: failed to read response: %v", requestID, err)
				results <- false
				return
			}

			success := resp.StatusCode == http.StatusOK && string(body) == "Success"
			if success {
				fmt.Printf("✅ Request %d successful\n", requestID)
			} else {
				fmt.Printf("❌ Request %d failed: status=%d, body=%s\n", requestID, resp.StatusCode, string(body))
			}

			results <- success
		}(i)
	}

	// Wait for all requests to complete
	wg.Wait()
	close(results)

	// Count successful requests
	successCount := 0
	for success := range results {
		if success {
			successCount++
		}
	}

	fmt.Printf("Concurrent requests: %d/%d successful\n", successCount, numRequests)

	if successCount != numRequests {
		t.Errorf("Expected all %d requests to succeed, got %d", numRequests, successCount)
	}

	// Check if at least one callback was received
	if !handler.isReceived() {
		t.Error("No callbacks were received")
	}

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		t.Errorf("Server shutdown error: %v", err)
	}

	// Wait for server to finish
	select {
	case <-serverDone:
		// Server stopped
	case <-time.After(6 * time.Second):
		t.Error("Server shutdown timed out")
	}

	fmt.Println("✅ Multiple concurrent test complete")
}
