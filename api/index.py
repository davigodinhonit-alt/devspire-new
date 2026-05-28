import sys
import os

# Ensure api/ directory is in Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
