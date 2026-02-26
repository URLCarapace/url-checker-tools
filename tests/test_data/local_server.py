#!/usr/bin/env python3
"""Local HTTP server for testing purposes."""

import socket
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


class TestHTTPServer:
    """Simple HTTP server for testing URL scanning."""

    def __init__(self, port=0, directory=None):
        """Initialize test server."""
        self.port = port
        self.directory = directory or Path(__file__).parent.parent / "test_data"
        self.server = None
        self.thread = None
        self.actual_port = None

    def start(self):
        """Start the HTTP server in a background thread."""
        # Find available port if not specified
        if self.port == 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", 0))
                s.listen(1)
                self.actual_port = s.getsockname()[1]
        else:
            self.actual_port = self.port

        # Create request handler that serves from our test directory
        class TestRequestHandler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(directory), **kwargs)

        directory = self.directory

        # Start server
        self.server = HTTPServer(("localhost", self.actual_port), TestRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        # Give server time to start
        time.sleep(0.1)

        return self.actual_port

    def stop(self):
        """Stop the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1)

    def get_url(self, filename):
        """Get URL for a test file."""
        if not self.actual_port:
            raise RuntimeError("Server not started")
        return f"http://localhost:{self.actual_port}/{filename}"

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def start_test_server(port=0):
    """Start a test HTTP server and return it."""
    server = TestHTTPServer(port=port)
    server.start()
    return server
