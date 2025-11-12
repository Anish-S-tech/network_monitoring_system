#!/usr/bin/env python3
"""
Network Traffic Management System - Backend Server
Run this script to start the Flask API server
"""

import os
import sys
from app import app

if __name__ == '__main__':
    print("Starting Network Traffic Management Backend...")
    print("Server will be available at: http://localhost:5000")
    print("API endpoints available at: http://localhost:5000/api/")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        app.run(debug=True, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        print("\nServer stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting server: {e}")
        sys.exit(1)