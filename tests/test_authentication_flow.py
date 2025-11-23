"""
Test suite for authentication flow and HTTP honeypot integration
Tests the login redirect from HTTP honeypot to dashboard success page
"""
import pytest
import requests
from urllib.parse import urlparse, parse_qs


HTTP_HONEYPOT_URL = "http://127.0.0.1:8081"
DASHBOARD_URL = "http://127.0.0.1:5001"


def _get_http(endpoint):
    """Helper to make GET requests to HTTP honeypot"""
    try:
        return requests.get(f"{HTTP_HONEYPOT_URL}{endpoint}", timeout=5, allow_redirects=False)
    except Exception as e:
        return None


def _post_http(endpoint, data):
    """Helper to make POST requests to HTTP honeypot"""
    try:
        return requests.post(f"{HTTP_HONEYPOT_URL}{endpoint}", data=data, timeout=5, allow_redirects=False)
    except Exception as e:
        return None


class TestAuthenticationFlow:
    """Test authentication flow and redirects"""
    
    def test_http_honeypot_accessible(self):
        """Test HTTP honeypot is accessible"""
        resp = _get_http("/")
        if resp is None:
            pytest.skip("HTTP honeypot not running at http://127.0.0.1:8081")
        assert resp.status_code in [200, 404], "HTTP honeypot should respond"
    
    def test_admin_login_page_accessible(self):
        """Test admin login page is accessible"""
        resp = _get_http("/admin")
        if resp is None:
            pytest.skip("HTTP honeypot not running")
        assert resp.status_code == 200, "Admin login page should be accessible"

    def test_weak_credentials_redirect(self):
        """Test that weak credentials redirect to success page"""
        resp = _post_http("/admin", {
            "username": "admin",
            "password": "admin"
        })
        
        if resp is None:
            pytest.skip("HTTP honeypot not running")
        
        # Should get a redirect (302)
        assert resp.status_code == 302, f"Expected 302 redirect, got {resp.status_code}"
        
        # Check redirect location
        location = resp.headers.get('Location', '')
        assert location, "Redirect location should be present"
        assert "5001" in location or "success" in location, "Should redirect to dashboard success page"
    
    def test_redirect_contains_session_id(self):
        """Test that redirect contains session ID parameter"""
        resp = _post_http("/admin", {
            "username": "admin",
            "password": "admin"
        })

        if resp is None:
            pytest.skip("HTTP honeypot not running")

        if resp.status_code != 302:
            pytest.skip("No redirect received")

        location = resp.headers.get('Location', '')
        assert "session_id" in location, "Redirect should contain session_id parameter"

    def test_redirect_contains_username(self):
        """Test that redirect contains username parameter"""
        resp = _post_http("/admin", {
            "username": "testuser",
            "password": "password"
        })

        if resp is None:
            pytest.skip("HTTP honeypot not running")

        if resp.status_code != 302:
            pytest.skip("No redirect received")

        location = resp.headers.get('Location', '')
        assert "username" in location, "Redirect should contain username parameter"

    def test_success_page_displays_session_info(self):
        """Test that success page displays session information"""
        # First, get a redirect from login
        resp = _post_http("/admin", {
            "username": "admin",
            "password": "admin"
        })
        
        if resp is None:
            pytest.skip("HTTP honeypot not running")
        
        if resp.status_code != 302:
            pytest.skip("No redirect received")
        
        location = resp.headers.get('Location', '')
        
        # Parse the redirect URL
        parsed = urlparse(location)
        params = parse_qs(parsed.query)
        
        # Verify parameters are present
        assert 'username' in params, "Username parameter should be in redirect"
        assert 'session_id' in params, "Session ID parameter should be in redirect"
        
        # Extract values
        username = params['username'][0]
        session_id = params['session_id'][0]
        
        assert username == "admin", "Username should match login credentials"
        assert len(session_id) > 0, "Session ID should not be empty"
    
    def test_dashboard_success_page_accessible(self):
        """Test dashboard success page is accessible"""
        resp = requests.get(f"{DASHBOARD_URL}/success", timeout=5)
        
        if resp is None:
            pytest.skip("Dashboard not running")
        
        assert resp.status_code == 200, "Success page should be accessible"
        assert "success" in resp.text.lower() or "authentication" in resp.text.lower(), \
            "Success page should contain success or authentication related content"
    
    def test_all_weak_credentials_redirect(self):
        """Test that all weak credentials redirect to success page"""
        weak_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("administrator", "admin"),
            ("test", "test"),
            ("guest", "guest"),
            ("demo", "demo")
        ]
        
        for username, password in weak_credentials:
            resp = _post_http("/admin", {
                "username": username,
                "password": password
            })
            
            if resp is None:
                pytest.skip("HTTP honeypot not running")
            
            assert resp.status_code == 302, \
                f"Credentials {username}:{password} should redirect (got {resp.status_code})"
            
            location = resp.headers.get('Location', '')
            assert location, f"Redirect location should be present for {username}:{password}"


class TestDashboardIntegration:
    """Test dashboard integration with honeypots"""
    
    def test_dashboard_api_stats_available(self):
        """Test dashboard API stats endpoint is available"""
        resp = requests.get(f"{DASHBOARD_URL}/api/stats", timeout=5)
        
        if resp is None:
            pytest.skip("Dashboard not running")
        
        assert resp.status_code == 200, "Stats API should be available"
        data = resp.json()
        assert isinstance(data, dict), "Stats should return a dictionary"
    
    def test_dashboard_api_connections_available(self):
        """Test dashboard API connections endpoint is available"""
        resp = requests.get(f"{DASHBOARD_URL}/api/recent-connections", timeout=5)
        
        if resp is None:
            pytest.skip("Dashboard not running")
        
        assert resp.status_code == 200, "Connections API should be available"
        data = resp.json()
        assert "connections" in data, "Response should contain connections key"
    
    def test_dashboard_api_alerts_available(self):
        """Test dashboard API alerts endpoint is available"""
        resp = requests.get(f"{DASHBOARD_URL}/api/alerts", timeout=5)
        
        if resp is None:
            pytest.skip("Dashboard not running")
        
        assert resp.status_code == 200, "Alerts API should be available"
        data = resp.json()
        assert "alerts" in data, "Response should contain alerts key"

