"""Common fixtures and configuration for tests."""
import os
import sys

# Add app directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app'))
