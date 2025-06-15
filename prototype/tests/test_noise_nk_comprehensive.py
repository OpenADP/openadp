#!/usr/bin/env python3
"""
Comprehensive tests for noise_nk.py module.

This test suite aims to achieve >80% code coverage for the Noise-NK protocol implementation,
focusing on security-critical paths and edge cases.
"""

import unittest
import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import noise_nk, crypto


class TestNoiseNKComprehensive(unittest.TestCase):
    """Comprehensive tests for Noise-NK protocol implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Generate test keypairs using the noise_nk module
        self.responder_keypair = noise_nk.generate_keypair()
        # For remote_static_key, we need to pass the key object, not raw bytes
        self.responder_public_key_obj = self.responder_keypair.public
        
        # Test messages
        self.test_message = b"Hello, secure world!"
        self.empty_message = b""
        self.large_message = b"X" * 10000

    def test_noise_nk_initialization(self):
        """Test NoiseNK initialization with different parameters."""
        # Test initiator
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        self.assertTrue(initiator.is_initiator)
        self.assertEqual(initiator.role, 'initiator')
        self.assertFalse(initiator.handshake_complete)
        
        # Test responder
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        self.assertFalse(responder.is_initiator)
        self.assertEqual(responder.role, 'responder')
        self.assertFalse(responder.handshake_complete)

    def test_noise_nk_handshake_complete_flow(self):
        """Test complete Noise-NK handshake flow."""
        # Initialize parties
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Step 1: Initiator sends handshake message
        handshake_msg = initiator.write_handshake_message(self.test_message)
        self.assertIsInstance(handshake_msg, bytes)
        self.assertGreater(len(handshake_msg), len(self.test_message))
        
        # Step 2: Responder processes handshake message
        received_payload = responder.read_handshake_message(handshake_msg)
        self.assertEqual(received_payload, self.test_message)
        
        # Step 3: Responder sends response
        response_msg = responder.write_handshake_message(b"Response payload")
        self.assertIsInstance(response_msg, bytes)
        
        # Step 4: Initiator processes response
        response_payload = initiator.read_handshake_message(response_msg)
        self.assertEqual(response_payload, b"Response payload")
        
        # Both sides should now have completed handshake
        self.assertTrue(initiator.is_handshake_complete())
        self.assertTrue(responder.is_handshake_complete())

    def test_noise_nk_transport_messages(self):
        """Test transport message encryption/decryption after handshake."""
        # Complete handshake first
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test transport messages
        test_messages = [
            b"First transport message",
            b"",  # Empty message
            b"X" * 1000,  # Large message
            b"\x00\x01\x02\x03",  # Binary data
        ]
        
        for msg in test_messages:
            with self.subTest(message_len=len(msg)):
                # Initiator -> Responder
                encrypted = initiator.encrypt(msg)
                self.assertIsInstance(encrypted, bytes)
                if msg:  # Non-empty messages should be different when encrypted
                    self.assertNotEqual(encrypted, msg)
                
                decrypted = responder.decrypt(encrypted)
                self.assertEqual(decrypted, msg)
                
                # Responder -> Initiator
                encrypted_resp = responder.encrypt(msg)
                self.assertIsInstance(encrypted_resp, bytes)
                if msg:
                    self.assertNotEqual(encrypted_resp, msg)
                
                decrypted_resp = initiator.decrypt(encrypted_resp)
                self.assertEqual(decrypted_resp, msg)

    def test_noise_nk_handshake_edge_cases(self):
        """Test handshake edge cases and error conditions."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Test with empty payload
        handshake_msg = initiator.write_handshake_message(b"")
        received_payload = responder.read_handshake_message(handshake_msg)
        self.assertEqual(received_payload, b"")
        
        # Test with large payload
        large_payload = b"L" * 5000
        response_msg = responder.write_handshake_message(large_payload)
        response_payload = initiator.read_handshake_message(response_msg)
        self.assertEqual(response_payload, large_payload)

    def test_noise_nk_invalid_initialization(self):
        """Test invalid initialization parameters."""
        # Test invalid role
        with self.assertRaises(ValueError):
            noise_nk.NoiseNK(role='invalid_role')
        
        # Test initiator without remote static key
        with self.assertRaises(ValueError):
            noise_nk.NoiseNK(role='initiator')

    def test_noise_nk_transport_before_handshake(self):
        """Test that transport messages fail before handshake completion."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        # Try to encrypt before handshake
        with self.assertRaises(RuntimeError):
            initiator.encrypt(b"premature message")
        
        # Try to decrypt before handshake
        with self.assertRaises(RuntimeError):
            initiator.decrypt(b"fake_ciphertext")

    def test_noise_nk_keypair_generation(self):
        """Test keypair generation."""
        keypair = noise_nk.generate_keypair()
        self.assertIsNotNone(keypair)
        self.assertIsNotNone(keypair.public)
        self.assertIsNotNone(keypair.private)
        
        # Test that generated keys are different
        keypair2 = noise_nk.generate_keypair()
        self.assertNotEqual(keypair.public.data, keypair2.public.data)

    def test_noise_nk_public_key_operations(self):
        """Test public key operations."""
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        public_key = responder.get_public_key()
        self.assertIsInstance(public_key, bytes)
        self.assertEqual(len(public_key), 32)  # X25519 public keys are 32 bytes

    def test_noise_nk_set_remote_public_key(self):
        """Test setting remote public key."""
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Generate another keypair for testing
        test_keypair = noise_nk.generate_keypair()
        test_public_key_bytes = test_keypair.public.data
        
        # Set remote public key using bytes (should convert internally)
        responder.set_remote_public_key(test_public_key_bytes)
        # This should not raise an exception

    def test_noise_nk_handshake_hash(self):
        """Test handshake hash generation."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Get handshake hashes
        init_hash = initiator.get_handshake_hash()
        resp_hash = responder.get_handshake_hash()
        
        # Both parties should have the same handshake hash
        self.assertEqual(init_hash, resp_hash)
        self.assertIsInstance(init_hash, bytes)
        self.assertGreater(len(init_hash), 0)

    def test_noise_nk_bidirectional_communication(self):
        """Test bidirectional communication after handshake."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test multiple rounds of bidirectional communication
        for round_num in range(5):
            with self.subTest(round=round_num):
                # Initiator -> Responder
                init_msg = f"Initiator message {round_num}".encode()
                encrypted_init = initiator.encrypt(init_msg)
                decrypted_init = responder.decrypt(encrypted_init)
                self.assertEqual(decrypted_init, init_msg)
                
                # Responder -> Initiator
                resp_msg = f"Responder message {round_num}".encode()
                encrypted_resp = responder.encrypt(resp_msg)
                decrypted_resp = initiator.decrypt(encrypted_resp)
                self.assertEqual(decrypted_resp, resp_msg)

    def test_noise_nk_state_isolation(self):
        """Test that different Noise states are properly isolated."""
        # Create multiple initiator-responder pairs
        pairs = []
        for i in range(3):
            resp_keypair = noise_nk.generate_keypair()
            
            initiator = noise_nk.NoiseNK(
                role='initiator',
                remote_static_key=resp_keypair.public
            )
            
            responder = noise_nk.NoiseNK(
                role='responder',
                local_static_key=resp_keypair
            )
            
            pairs.append((initiator, responder))
        
        # Complete handshakes for all pairs
        for i, (initiator, responder) in enumerate(pairs):
            handshake_msg = initiator.write_handshake_message(f"init{i}".encode())
            responder.read_handshake_message(handshake_msg)
            response_msg = responder.write_handshake_message(f"resp{i}".encode())
            initiator.read_handshake_message(response_msg)
        
        # Test that messages from one pair can't be decrypted by another
        msg = b"secret message"
        encrypted_0 = pairs[0][0].encrypt(msg)
        
        # Should decrypt correctly with matching responder
        decrypted_correct = pairs[0][1].decrypt(encrypted_0)
        self.assertEqual(decrypted_correct, msg)
        
        # Should fail with wrong responder
        with self.assertRaises(Exception):
            pairs[1][1].decrypt(encrypted_0)

    def test_noise_nk_error_recovery(self):
        """Test error recovery and state consistency."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Complete handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Send a valid message
        valid_msg = b"valid message"
        encrypted_valid = initiator.encrypt(valid_msg)
        decrypted_valid = responder.decrypt(encrypted_valid)
        self.assertEqual(decrypted_valid, valid_msg)
        
        # Try to decrypt corrupted message
        corrupted_msg = encrypted_valid[:-1] + b"\x00"  # Corrupt last byte
        with self.assertRaises(Exception):
            responder.decrypt(corrupted_msg)
        
        # Verify that valid communication can continue after error
        another_valid_msg = b"another valid message"
        encrypted_another = initiator.encrypt(another_valid_msg)
        decrypted_another = responder.decrypt(encrypted_another)
        self.assertEqual(decrypted_another, another_valid_msg)

    def test_noise_nk_performance_characteristics(self):
        """Test performance characteristics with various message sizes."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test with various message sizes
        sizes = [0, 1, 16, 64, 256, 1024, 4096, 16384]
        
        for size in sizes:
            with self.subTest(size=size):
                test_msg = b"X" * size
                encrypted = initiator.encrypt(test_msg)
                decrypted = responder.decrypt(encrypted)
                self.assertEqual(decrypted, test_msg)
                
                # Check that encryption adds reasonable overhead
                if size > 0:
                    overhead = len(encrypted) - len(test_msg)
                    self.assertGreater(overhead, 0)  # Should have some overhead
                    self.assertLess(overhead, 100)   # But not excessive

    def test_noise_nk_prologue_handling(self):
        """Test prologue handling."""
        prologue = b"test prologue data"
        
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj,
            prologue=prologue
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair,
            prologue=prologue
        )
        
        # Should be able to complete handshake with matching prologues
        handshake_msg = initiator.write_handshake_message(b"test")
        received_payload = responder.read_handshake_message(handshake_msg)
        self.assertEqual(received_payload, b"test")

    def test_noise_nk_handshake_state_errors(self):
        """Test handshake state error conditions."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Complete handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Try to write handshake message after completion
        with self.assertRaises(RuntimeError):
            initiator.write_handshake_message(b"too late")
        
        # Try to read handshake message after completion
        with self.assertRaises(RuntimeError):
            responder.read_handshake_message(b"fake message")

    def test_noise_nk_main_function_coverage(self):
        """Test the main function and test_noise_nk to ensure they run without errors."""
        # Run the noise_nk module as a script to cover the main function
        import subprocess
        import sys
        import os
        
        try:
            # Get the path to the noise_nk module
            noise_nk_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'openadp', 'noise_nk.py')
            
            # Run the module as a script
            result = subprocess.run(
                [sys.executable, noise_nk_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check that it ran successfully
            self.assertEqual(result.returncode, 0, f"Script failed with stderr: {result.stderr}")
            
            # Verify that the test ran successfully
            self.assertIn("Testing Simple NoiseNK Implementation", result.stdout)
            self.assertIn("All tests passed", result.stdout)
            
        except subprocess.TimeoutExpired:
            self.fail("noise_nk script timed out")
        except Exception as e:
            self.fail(f"Failed to run noise_nk script: {e}")

    def test_noise_nk_associated_data_encryption(self):
        """Test encryption/decryption with associated data."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test encryption with associated data
        plaintext = b"Secret message with associated data"
        associated_data = b"metadata_header"
        
        # Encrypt with associated data
        encrypted = initiator.encrypt(plaintext, associated_data)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, plaintext)
        
        # Decrypt with same associated data
        decrypted = responder.decrypt(encrypted, associated_data)
        self.assertEqual(decrypted, plaintext)
        
        # Try to decrypt with wrong associated data (should fail)
        wrong_associated_data = b"wrong_metadata"
        with self.assertRaises(Exception):
            responder.decrypt(encrypted, wrong_associated_data)
        
        # Try to decrypt with no associated data when it was encrypted with some
        with self.assertRaises(Exception):
            responder.decrypt(encrypted, b"")

    def test_noise_nk_multiple_message_exchange(self):
        """Test multiple message exchange patterns."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test multiple message exchange (similar to the main function)
        messages = [
            (b"Message 1", "Client -> Server"),
            (b"ACK 1", "Server -> Client"),
            (b"Message 2 with more data", "Client -> Server"),
            (b"Final ACK", "Server -> Client")
        ]
        
        for msg, direction in messages:
            with self.subTest(message=msg, direction=direction):
                if "Client -> Server" in direction:
                    encrypted = initiator.encrypt(msg)
                    decrypted = responder.decrypt(encrypted)
                else:
                    encrypted = responder.encrypt(msg)
                    decrypted = initiator.decrypt(encrypted)
                
                self.assertEqual(decrypted, msg)

    def test_noise_nk_cipher_state_properties(self):
        """Test properties of cipher states after handshake."""
        # Complete handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Verify cipher states exist
        self.assertIsNotNone(initiator.send_cipher)
        self.assertIsNotNone(initiator.recv_cipher)
        self.assertIsNotNone(responder.send_cipher)
        self.assertIsNotNone(responder.recv_cipher)
        
        # Verify they are different objects
        self.assertNotEqual(initiator.send_cipher, initiator.recv_cipher)
        self.assertNotEqual(responder.send_cipher, responder.recv_cipher)

    def test_noise_nk_handshake_message_tracking(self):
        """Test handshake message tracking attributes."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Initially, no message tracking attributes should exist
        self.assertFalse(hasattr(initiator, '_wrote_message'))
        self.assertFalse(hasattr(initiator, '_read_message'))
        self.assertFalse(hasattr(responder, '_wrote_message'))
        self.assertFalse(hasattr(responder, '_read_message'))
        
        # After initiator writes message
        handshake_msg = initiator.write_handshake_message(b"init")
        self.assertTrue(hasattr(initiator, '_wrote_message'))
        self.assertFalse(hasattr(initiator, '_read_message'))
        
        # After responder reads message
        responder.read_handshake_message(handshake_msg)
        self.assertTrue(hasattr(responder, '_read_message'))
        self.assertFalse(hasattr(responder, '_wrote_message'))
        
        # After responder writes response
        response_msg = responder.write_handshake_message(b"resp")
        self.assertTrue(hasattr(responder, '_wrote_message'))
        self.assertTrue(hasattr(responder, '_read_message'))
        
        # After initiator reads response - handshake should be complete
        initiator.read_handshake_message(response_msg)
        self.assertTrue(hasattr(initiator, '_read_message'))
        self.assertTrue(hasattr(initiator, '_wrote_message'))
        self.assertTrue(initiator.is_handshake_complete())
        self.assertTrue(responder.is_handshake_complete())

    def test_noise_nk_get_handshake_hash_before_completion(self):
        """Test that get_handshake_hash fails before handshake completion."""
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        # Should fail before handshake completion
        with self.assertRaises(RuntimeError):
            initiator.get_handshake_hash()

    def test_noise_nk_responder_cipher_assignment(self):
        """Test that responder gets correct cipher assignment."""
        # This tests the else branch in _finalize_handshake
        initiator = noise_nk.NoiseNK(
            role='initiator',
            remote_static_key=self.responder_public_key_obj
        )
        
        responder = noise_nk.NoiseNK(
            role='responder',
            local_static_key=self.responder_keypair
        )
        
        # Complete handshake
        handshake_msg = initiator.write_handshake_message(b"init")
        responder.read_handshake_message(handshake_msg)
        response_msg = responder.write_handshake_message(b"resp")
        initiator.read_handshake_message(response_msg)
        
        # Test that responder's cipher assignment is opposite of initiator's
        # (This tests the else branch in _finalize_handshake)
        test_msg = b"test cipher assignment"
        
        # Initiator encrypts, responder decrypts
        encrypted = initiator.encrypt(test_msg)
        decrypted = responder.decrypt(encrypted)
        self.assertEqual(decrypted, test_msg)
        
        # Responder encrypts, initiator decrypts
        encrypted_resp = responder.encrypt(test_msg)
        decrypted_resp = initiator.decrypt(encrypted_resp)
        self.assertEqual(decrypted_resp, test_msg)


if __name__ == '__main__':
    unittest.main() 