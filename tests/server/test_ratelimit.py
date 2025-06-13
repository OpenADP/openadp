#!/usr/bin/env python3
"""
Test rate limiting functionality for Phase 3 authentication.

Tests that per-user and per-IP rate limiting works correctly and 
prevents abuse while allowing legitimate usage.
"""

import unittest
import sys
import os
import time
from unittest.mock import patch

# Add the src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'prototype', 'src'))

# Import the rate limiting function
from server.jsonrpc_server import check_rate_limit, user_request_counts, ip_request_counts


class TestRateLimit(unittest.TestCase):
    """Test rate limiting functionality."""
    
    def setUp(self):
        """Set up test data."""
        # Clear rate limiting caches
        user_request_counts.clear()
        ip_request_counts.clear()
        
        # Test data
        self.alice_sub = "alice-oauth-sub-12345"
        self.bob_sub = "bob-oauth-sub-67890"
        self.client_ip1 = "192.168.1.100"
        self.client_ip2 = "192.168.1.101"
    
    def tearDown(self):
        """Clean up after tests."""
        user_request_counts.clear()
        ip_request_counts.clear()
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_USER_PER_MINUTE', 3)
    def test_user_rate_limit_enforcement(self):
        """Test that per-user rate limiting works correctly."""
        # Alice makes requests up to the limit
        for i in range(3):
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error, f"Request {i+1} should be allowed")
        
        # Next request should be rate limited
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNotNone(error)
        self.assertIn("Rate limit exceeded", error)
        self.assertIn(self.alice_sub, error)
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_IP_PER_MINUTE', 5)
    def test_ip_rate_limit_enforcement(self):
        """Test that per-IP rate limiting works correctly."""
        # Make requests from same IP up to the limit
        for i in range(5):
            error = check_rate_limit(None, self.client_ip1)  # Unauthenticated requests
            self.assertIsNone(error, f"Request {i+1} should be allowed")
        
        # Next request should be rate limited
        error = check_rate_limit(None, self.client_ip1)
        self.assertIsNotNone(error)
        self.assertIn("Rate limit exceeded", error)
        self.assertIn(self.client_ip1, error)
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_USER_PER_MINUTE', 3)
    def test_user_isolation(self):
        """Test that rate limits are isolated per user."""
        # Alice uses up her rate limit
        for i in range(3):
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Alice's next request should be blocked
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNotNone(error)
        
        # But Bob should still be able to make requests
        error = check_rate_limit(self.bob_sub, self.client_ip1)
        self.assertIsNone(error, "Bob should not be affected by Alice's rate limit")
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_IP_PER_MINUTE', 5)
    def test_ip_isolation(self):
        """Test that rate limits are isolated per IP address."""
        # Client IP 1 uses up its rate limit
        for i in range(5):
            error = check_rate_limit(None, self.client_ip1)
            self.assertIsNone(error)
        
        # Client IP 1's next request should be blocked
        error = check_rate_limit(None, self.client_ip1)
        self.assertIsNotNone(error)
        
        # But Client IP 2 should still be able to make requests
        error = check_rate_limit(None, self.client_ip2)
        self.assertIsNone(error, "IP2 should not be affected by IP1's rate limit")
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_USER_PER_MINUTE', 3)
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_IP_PER_MINUTE', 5)
    def test_both_limits_enforced(self):
        """Test that both user and IP limits are enforced independently."""
        # Alice makes requests (both user and IP counters increment)
        for i in range(3):
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Alice hits user rate limit
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNotNone(error)
        self.assertIn(self.alice_sub, error)
        
        # Bob can still make requests from same IP (2 more to reach IP limit)
        for i in range(2):
            error = check_rate_limit(self.bob_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Now IP limit is reached, so even Bob is blocked
        error = check_rate_limit(self.bob_sub, self.client_ip1)
        self.assertIsNotNone(error)
        self.assertIn(self.client_ip1, error)
    
    @patch('time.time')
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_USER_PER_MINUTE', 2)
    def test_time_window_sliding(self, mock_time):
        """Test that the rate limit window slides properly."""
        # Start at time 0
        mock_time.return_value = 0
        
        # Alice makes 2 requests at time 0
        for i in range(2):
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Alice hits rate limit
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNotNone(error)
        
        # Move forward 30 seconds - still within 1-minute window
        mock_time.return_value = 30
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNotNone(error, "Should still be rate limited after 30 seconds")
        
        # Move forward 61 seconds - outside 1-minute window
        mock_time.return_value = 61
        error = check_rate_limit(self.alice_sub, self.client_ip1)
        self.assertIsNone(error, "Should be allowed after 61 seconds")
    
    @patch('server.jsonrpc_server.MAX_REQUESTS_PER_USER_PER_MINUTE', 2)
    def test_rate_limit_cleanup(self):
        """Test that old rate limit entries are cleaned up."""
        # Make some requests
        for i in range(2):
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Verify requests are recorded
        self.assertEqual(len(user_request_counts[self.alice_sub]), 2)
        self.assertEqual(len(ip_request_counts[self.client_ip1]), 2)
        
        # Simulate time passing (mock the current time to be 61 seconds later)
        import time
        future_time = time.time() + 61
        
        with patch('time.time', return_value=future_time):
            # Make another request - this should trigger cleanup
            error = check_rate_limit(self.alice_sub, self.client_ip1)
            self.assertIsNone(error)
        
        # Old entries should be cleaned up, only the new request should remain
        self.assertEqual(len(user_request_counts[self.alice_sub]), 1)
        self.assertEqual(len(ip_request_counts[self.client_ip1]), 1)
    
    def test_unauthenticated_requests(self):
        """Test that unauthenticated requests only count against IP limits."""
        # Make unauthenticated requests
        for i in range(3):
            error = check_rate_limit(None, self.client_ip1)
            self.assertIsNone(error)
        
        # Verify only IP counter was incremented
        self.assertEqual(len(ip_request_counts[self.client_ip1]), 3)
        self.assertEqual(len(user_request_counts), 0)  # No user counters


if __name__ == '__main__':
    unittest.main() 