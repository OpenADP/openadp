#!/usr/bin/env python3
"""
Test script for encrypt.py that bypasses interactive password prompt
"""
import sys
import os

# Mock getpass to return our test password
class MockGetpass:
    def getpass(self, prompt):
        print(prompt + "foo")  # Show what password we're using
        return "foo"

# Replace getpass module
sys.modules['getpass'] = MockGetpass()

# Now import and run encrypt
import encrypt
encrypt.encrypt_file("test_file.txt", "foo") 