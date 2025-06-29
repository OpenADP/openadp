import sys
import os

# Add the OpenADP SDK to the Python path for all tests
sdk_path = os.path.join(os.path.dirname(__file__), '..', '..', 'sdk', 'python')
sys.path.insert(0, sdk_path) 