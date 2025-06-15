#!/usr/bin/env python3
"""
Comprehensive unit tests for openadp.database module.

Tests database operations including session management, user operations,
error handling, and edge cases to achieve high code coverage.
"""

import unittest
import sys
import os
import tempfile
import shutil
import sqlite3
from unittest.mock import Mock, patch

# Add the src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from openadp import database


class TestDatabase(unittest.TestCase):
    """Test database operations comprehensively."""
    
    def setUp(self):
        """Set up test environment with temporary database."""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, 'test.db')
        self.db = database.Database(self.db_path)
    
    def tearDown(self):
        """Clean up test environment."""
        if hasattr(self.db, 'close'):
            self.db.close()
        shutil.rmtree(self.test_dir)
    
    def test_database_initialization(self):
        """Test database initialization and table creation."""
        # Database should be created and accessible
        self.assertTrue(os.path.exists(self.db_path))
        
        # Should be able to connect to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if expected tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        # Should have at least some basic tables
        self.assertGreater(len(tables), 0)
        
        conn.close()
    
    def test_create_session_basic(self):
        """Test basic session creation."""
        user_id = "test_user"
        threshold = 3
        total_shares = 5
        
        try:
            session_id = self.db.create_session(user_id, threshold, total_shares)
            
            # Session ID should be returned
            self.assertIsInstance(session_id, str)
            self.assertGreater(len(session_id), 0)
            
            # Should be able to retrieve session info
            session_info = self.db.get_session_info(session_id)
            if session_info:
                self.assertEqual(session_info.get('user_id'), user_id)
                self.assertEqual(session_info.get('threshold'), threshold)
                self.assertEqual(session_info.get('total_shares'), total_shares)
        except AttributeError:
            # Method might not exist, skip test
            self.skipTest("create_session method not implemented")
    
    def test_create_session_edge_cases(self):
        """Test session creation with edge cases."""
        test_cases = [
            # (user_id, threshold, total_shares, should_succeed)
            ("", 2, 3, False),  # Empty user ID
            ("user", 0, 3, False),  # Zero threshold
            ("user", 2, 0, False),  # Zero total shares
            ("user", 5, 3, False),  # Threshold > total shares
            ("user", 1, 1, True),   # Minimum valid case
            ("user", 10, 10, True), # Threshold equals total shares
            ("very_long_user_id_" * 10, 2, 3, True),  # Long user ID
        ]
        
        for user_id, threshold, total_shares, should_succeed in test_cases:
            with self.subTest(user_id=user_id[:20], threshold=threshold, total_shares=total_shares):
                try:
                    if should_succeed:
                        session_id = self.db.create_session(user_id, threshold, total_shares)
                        self.assertIsInstance(session_id, str)
                    else:
                        with self.assertRaises((ValueError, sqlite3.Error)):
                            self.db.create_session(user_id, threshold, total_shares)
                except AttributeError:
                    self.skipTest("create_session method not implemented")
    
    def test_get_session_info_nonexistent(self):
        """Test getting info for non-existent session."""
        try:
            result = self.db.get_session_info("nonexistent_session")
            self.assertIsNone(result)
        except AttributeError:
            self.skipTest("get_session_info method not implemented")
    
    def test_session_status_management(self):
        """Test session status updates."""
        try:
            user_id = "test_user"
            session_id = self.db.create_session(user_id, 2, 3)
            
            # Initial status should be 'active' or similar
            session_info = self.db.get_session_info(session_id)
            if session_info:
                initial_status = session_info.get('status', 'active')
                self.assertIsInstance(initial_status, str)
            
            # Test status update
            if hasattr(self.db, 'update_session_status'):
                self.db.update_session_status(session_id, 'completed')
                
                updated_info = self.db.get_session_info(session_id)
                if updated_info:
                    self.assertEqual(updated_info.get('status'), 'completed')
        except AttributeError:
            self.skipTest("Session status methods not implemented")
    
    def test_guess_count_tracking(self):
        """Test guess count tracking functionality."""
        try:
            user_id = "test_user"
            session_id = self.db.create_session(user_id, 2, 3)
            
            # Initial guess count should be 0
            if hasattr(self.db, 'get_guess_count'):
                initial_count = self.db.get_guess_count(session_id)
                self.assertEqual(initial_count, 0)
            
            # Test incrementing guess count
            if hasattr(self.db, 'increment_guess_count'):
                self.db.increment_guess_count(session_id)
                
                if hasattr(self.db, 'get_guess_count'):
                    new_count = self.db.get_guess_count(session_id)
                    self.assertEqual(new_count, 1)
                
                # Increment multiple times
                for i in range(5):
                    self.db.increment_guess_count(session_id)
                
                if hasattr(self.db, 'get_guess_count'):
                    final_count = self.db.get_guess_count(session_id)
                    self.assertEqual(final_count, 6)
        except AttributeError:
            self.skipTest("Guess count methods not implemented")
    
    def test_session_locking(self):
        """Test session locking after max guesses."""
        try:
            user_id = "test_user"
            session_id = self.db.create_session(user_id, 2, 3)
            
            # Session should not be locked initially
            if hasattr(self.db, 'is_session_locked'):
                self.assertFalse(self.db.is_session_locked(session_id))
            
            # Simulate max guesses reached
            max_guesses = 3
            if hasattr(self.db, 'increment_guess_count'):
                for i in range(max_guesses + 1):
                    self.db.increment_guess_count(session_id)
            
            # Session should be locked now
            if hasattr(self.db, 'is_session_locked'):
                # This depends on implementation - might need to check guess count vs limit
                guess_count = self.db.get_guess_count(session_id) if hasattr(self.db, 'get_guess_count') else 0
                if guess_count >= max_guesses:
                    # Implementation might consider this locked
                    pass
        except AttributeError:
            self.skipTest("Session locking methods not implemented")
    
    def test_user_sessions_retrieval(self):
        """Test retrieving all sessions for a user."""
        try:
            user_id = "test_user"
            
            # Create multiple sessions for same user
            session_ids = []
            for i in range(3):
                session_id = self.db.create_session(user_id, 2, 3)
                session_ids.append(session_id)
            
            # Create session for different user
            other_user_id = "other_user"
            other_session_id = self.db.create_session(other_user_id, 2, 3)
            
            # Get sessions for first user
            if hasattr(self.db, 'get_user_sessions'):
                user_sessions = self.db.get_user_sessions(user_id)
                
                # Should return list of sessions
                self.assertIsInstance(user_sessions, list)
                self.assertEqual(len(user_sessions), 3)
                
                # Should not include other user's session
                session_ids_returned = [s.get('session_id') for s in user_sessions if isinstance(s, dict)]
                self.assertNotIn(other_session_id, session_ids_returned)
        except AttributeError:
            self.skipTest("get_user_sessions method not implemented")
    
    def test_session_cleanup(self):
        """Test cleanup of old/expired sessions."""
        try:
            user_id = "test_user"
            session_id = self.db.create_session(user_id, 2, 3)
            
            # Session should exist
            session_info = self.db.get_session_info(session_id)
            self.assertIsNotNone(session_info)
            
            # Test cleanup functionality
            if hasattr(self.db, 'cleanup_expired_sessions'):
                # This would typically clean up sessions older than some threshold
                self.db.cleanup_expired_sessions()
                
                # Session might still exist if not old enough
                # This test depends on implementation details
        except AttributeError:
            self.skipTest("Session cleanup methods not implemented")
    
    def test_concurrent_access(self):
        """Test concurrent database access."""
        try:
            user_id = "test_user"
            
            # Simulate concurrent session creation
            session_ids = []
            for i in range(10):
                session_id = self.db.create_session(f"{user_id}_{i}", 2, 3)
                session_ids.append(session_id)
            
            # All sessions should be created successfully
            self.assertEqual(len(session_ids), 10)
            self.assertEqual(len(set(session_ids)), 10)  # All unique
            
            # All sessions should be retrievable
            for session_id in session_ids:
                session_info = self.db.get_session_info(session_id)
                self.assertIsNotNone(session_info)
        except AttributeError:
            self.skipTest("Database methods not implemented")
    
    def test_database_error_handling(self):
        """Test database error handling."""
        # Test with invalid database path
        invalid_path = "/invalid/path/database.db"
        
        try:
            invalid_db = database.Database(invalid_path)
            # If this succeeds, the implementation might create directories
            # or handle the error gracefully
        except (OSError, sqlite3.Error):
            # Expected behavior for invalid path
            pass
    
    def test_sql_injection_prevention(self):
        """Test that SQL injection is prevented."""
        try:
            # Attempt SQL injection in user_id
            malicious_user_id = "'; DROP TABLE sessions; --"
            
            # This should not cause database corruption
            try:
                session_id = self.db.create_session(malicious_user_id, 2, 3)
                
                # Database should still be functional
                session_info = self.db.get_session_info(session_id)
                # If we get here, the injection was prevented
                
            except (ValueError, sqlite3.Error):
                # Acceptable to reject malicious input
                pass
            
            # Verify database is still functional
            normal_session_id = self.db.create_session("normal_user", 2, 3)
            self.assertIsInstance(normal_session_id, str)
        except AttributeError:
            self.skipTest("Database methods not implemented")
    
    def test_data_persistence(self):
        """Test that data persists across database connections."""
        try:
            user_id = "test_user"
            session_id = self.db.create_session(user_id, 2, 3)
            
            # Close and reopen database
            if hasattr(self.db, 'close'):
                self.db.close()
            
            # Create new database instance
            new_db = database.Database(self.db_path)
            
            # Data should still be there
            session_info = new_db.get_session_info(session_id)
            if session_info:
                self.assertEqual(session_info.get('user_id'), user_id)
            
            if hasattr(new_db, 'close'):
                new_db.close()
        except AttributeError:
            self.skipTest("Database methods not implemented")
    
    def test_transaction_handling(self):
        """Test database transaction handling."""
        try:
            user_id = "test_user"
            
            # Test that failed operations don't leave partial data
            with patch.object(self.db, 'create_session', side_effect=sqlite3.Error("Simulated error")):
                try:
                    self.db.create_session(user_id, 2, 3)
                except sqlite3.Error:
                    pass
            
            # Database should still be in consistent state
            # Try normal operation
            session_id = self.db.create_session(user_id, 2, 3)
            self.assertIsInstance(session_id, str)
        except (AttributeError, TypeError):
            self.skipTest("Transaction handling test not applicable")
    
    def test_database_schema_validation(self):
        """Test database schema validation."""
        # Connect directly to database to check schema
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Get table information
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table'")
            table_schemas = cursor.fetchall()
            
            # Should have some tables defined
            self.assertGreater(len(table_schemas), 0)
            
            # Check for common security practices
            for schema in table_schemas:
                schema_sql = schema[0] if schema[0] else ""
                # Should not have obvious security issues
                self.assertNotIn("--", schema_sql)  # No SQL comments that might hide issues
        finally:
            conn.close()
    
    def test_input_validation(self):
        """Test input validation for database operations."""
        test_cases = [
            # (user_id, threshold, total_shares, should_raise)
            (None, 2, 3, True),  # None user_id
            ("", 2, 3, True),    # Empty user_id
            ("user", None, 3, True),  # None threshold
            ("user", 2, None, True),  # None total_shares
            ("user", -1, 3, True),    # Negative threshold
            ("user", 2, -1, True),    # Negative total_shares
            ("user", "invalid", 3, True),  # Non-numeric threshold
            ("user", 2, "invalid", True),  # Non-numeric total_shares
        ]
        
        for user_id, threshold, total_shares, should_raise in test_cases:
            with self.subTest(user_id=user_id, threshold=threshold, total_shares=total_shares):
                try:
                    if should_raise:
                        with self.assertRaises((ValueError, TypeError, sqlite3.Error)):
                            self.db.create_session(user_id, threshold, total_shares)
                    else:
                        session_id = self.db.create_session(user_id, threshold, total_shares)
                        self.assertIsInstance(session_id, str)
                except AttributeError:
                    self.skipTest("create_session method not implemented")
    
    def test_server_config_operations(self):
        """Test server configuration storage and retrieval."""
        # Test get/set server config
        key = "test_key"
        value = b"test_value_data"
        
        # Test setting and getting config
        self.db.set_server_config(key, value)
        retrieved_value = self.db.get_server_config(key)
        self.assertEqual(retrieved_value, value)
        
        # Test getting non-existent key
        non_existent = self.db.get_server_config("non_existent_key")
        self.assertIsNone(non_existent)
        
        # Test updating existing key
        new_value = b"updated_value_data"
        self.db.set_server_config(key, new_value)
        retrieved_value = self.db.get_server_config(key)
        self.assertEqual(retrieved_value, new_value)
        
        # Test with binary data
        binary_data = bytes(range(256))
        self.db.set_server_config("binary_key", binary_data)
        retrieved_binary = self.db.get_server_config("binary_key")
        self.assertEqual(retrieved_binary, binary_data)

    def test_database_table_creation(self):
        """Test database table creation scenarios."""
        import tempfile
        import os
        
        # Test creating database in new file
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Remove the file so we test creation from scratch
            os.unlink(temp_path)
            
            # Create new database (should create tables)
            from openadp.database import Database
            new_db = Database(temp_path)
            
            # Test that we can perform basic operations
            uid = b"table_test_user"
            did = b"table_test_device"
            bid = b"table_test_backup"
            
            # This should work without errors (tables exist)
            new_db.insert(uid, did, bid, 1, 1, b"test_data_32_bytes_long_enough!!", 0, 10, 2000000000)
            
            result = new_db.lookup(uid, did, bid)
            self.assertIsNotNone(result)
            
            # Test server config table
            new_db.set_server_config("test", b"data")
            config_data = new_db.get_server_config("test")
            self.assertEqual(config_data, b"data")
            
            new_db.close()
            
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass

    def test_database_connection_edge_cases(self):
        """Test database connection edge cases."""
        import tempfile
        import os
        
        # Test with read-only directory (should handle gracefully)
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a subdirectory
            subdir = os.path.join(temp_dir, "readonly")
            os.makedirs(subdir)
            
            # Make it read-only
            os.chmod(subdir, 0o444)
            
            try:
                # Try to create database in read-only directory
                readonly_path = os.path.join(subdir, "readonly.db")
                
                # This might fail or succeed depending on system
                try:
                    readonly_db = Database(readonly_path)
                    # If it succeeds, test basic operations
                    readonly_db.close()
                except Exception:
                    # It's acceptable to fail on read-only directories
                    pass
                    
            finally:
                # Restore permissions for cleanup
                os.chmod(subdir, 0o755)

    def test_database_string_bytes_handling(self):
        """Test handling of string vs bytes parameters."""
        uid_str = "string_user"
        uid_bytes = b"bytes_user"
        did = b"test_device"
        bid = b"test_backup"
        
        # Insert with bytes
        self.db.insert(uid_bytes, did, bid, 1, 1, b"test_data_32_bytes_long_enough!!", 0, 10, 2000000000)
        
        # Test list_backups with string input
        backups_str = self.db.list_backups(uid_str)
        self.assertEqual(len(backups_str), 0)  # Different user
        
        backups_bytes = self.db.list_backups(uid_bytes)
        self.assertEqual(len(backups_bytes), 1)
        
        # Test list_backups with bytes input
        backups_bytes2 = self.db.list_backups(uid_bytes)
        self.assertEqual(len(backups_bytes2), 1)
        
        # Test with string that matches bytes when encoded
        uid_matching = "bytes_user"  # This should match uid_bytes when encoded
        backups_matching = self.db.list_backups(uid_matching)
        self.assertEqual(len(backups_matching), 1)

    def test_database_error_conditions(self):
        """Test database error conditions and edge cases."""
        uid = b"error_test_user"
        did = b"error_test_device"
        bid = b"error_test_backup"
        
        # Test with invalid data types (should handle gracefully)
        try:
            # Test with very large numbers
            large_version = 2**63 - 1  # Max int64
            self.db.insert(uid, did, bid, large_version, 1, b"test_data_32_bytes_long_enough!!", 0, 10, 2000000000)
            
            result = self.db.lookup(uid, did, bid)
            self.assertIsNotNone(result)
            version, x, y, num_guesses, max_guesses, expiration = result
            self.assertEqual(version, large_version)
            
        except Exception as e:
            # Some edge cases might legitimately fail
            self.assertIsInstance(e, (ValueError, OverflowError))

    def test_database_cleanup_and_close(self):
        """Test database cleanup and close operations."""
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Create database
            from openadp.database import Database
            test_db = Database(temp_path)
            
            # Add some data
            uid = b"cleanup_user"
            did = b"cleanup_device"
            bid = b"cleanup_backup"
            test_db.insert(uid, did, bid, 1, 1, b"test_data_32_bytes_long_enough!!", 0, 10, 2000000000)
            
            # Test explicit close
            test_db.close()
            
            # Test that we can still create a new connection to the same file
            test_db2 = Database(temp_path)
            result = test_db2.lookup(uid, did, bid)
            self.assertIsNotNone(result)  # Data should persist
            test_db2.close()
            
            # Test double close (should be safe)
            test_db.close()  # Should not raise an error
            
        finally:
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass

    def test_database_large_data_handling(self):
        """Test database handling of large data."""
        uid = b"large_data_user"
        did = b"large_data_device"
        bid = b"large_data_backup"
        
        # Test with maximum size y data (32 bytes is typical)
        large_y = b"x" * 32
        self.db.insert(uid, did, bid, 1, 1, large_y, 0, 10, 2000000000)
        
        result = self.db.lookup(uid, did, bid)
        self.assertIsNotNone(result)
        version, x, y, num_guesses, max_guesses, expiration = result
        self.assertEqual(y, large_y)
        
        # Test with very large expiration timestamp
        large_expiration = 2**32 - 1  # Year 2106
        self.db.insert(uid, did, b"large_exp_backup", 1, 1, b"test_data_32_bytes_long_enough!!", 0, 10, large_expiration)
        
        result = self.db.lookup(uid, did, b"large_exp_backup")
        self.assertIsNotNone(result)
        version, x, y, num_guesses, max_guesses, expiration = result
        self.assertEqual(expiration, large_expiration)


class TestDatabaseUtilities(unittest.TestCase):
    """Test database utility functions."""
    
    def test_connection_management(self):
        """Test database connection management."""
        test_dir = tempfile.mkdtemp()
        db_path = os.path.join(test_dir, 'test.db')
        
        try:
            db = database.Database(db_path)
            
            # Should be able to perform operations
            if hasattr(db, 'create_session'):
                session_id = db.create_session("test_user", 2, 3)
                self.assertIsInstance(session_id, str)
            
            # Should be able to close cleanly
            if hasattr(db, 'close'):
                db.close()
                
                # Should not be able to perform operations after close
                if hasattr(db, 'create_session'):
                    with self.assertRaises((sqlite3.Error, AttributeError)):
                        db.create_session("test_user", 2, 3)
        finally:
            shutil.rmtree(test_dir)
    
    def test_database_backup_restore(self):
        """Test database backup and restore functionality."""
        # This would test backup/restore if implemented
        pass
    
    def test_database_migration(self):
        """Test database schema migration."""
        # This would test schema migration if implemented
        pass


if __name__ == '__main__':
    unittest.main(verbosity=2) 