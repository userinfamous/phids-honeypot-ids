"""
Test suite for UI consistency and new pages
Tests the success page, error page, and navigation bar consistency
"""
import pytest
import requests
from bs4 import BeautifulSoup


BASE_URL = "http://127.0.0.1:5001"


def _get(endpoint):
    """Helper to make GET requests with timeout"""
    try:
        return requests.get(f"{BASE_URL}{endpoint}", timeout=5)
    except Exception as e:
        return None


def _check_navbar(html_content):
    """Check if navbar is present and has required links"""
    soup = BeautifulSoup(html_content, 'html.parser')
    navbar = soup.find('nav', class_='navbar')
    
    if not navbar:
        return False, "Navbar not found"
    
    # Check for brand
    brand = navbar.find('a', class_='navbar-brand')
    if not brand or 'PHIDS' not in brand.text:
        return False, "PHIDS brand not found in navbar"
    
    # Check for required links
    links = navbar.find_all('a', class_='nav-link')
    link_texts = [link.text.strip() for link in links]
    
    required_links = ['Dashboard', 'Attacks', 'Info']
    for required in required_links:
        if required not in link_texts:
            return False, f"Required link '{required}' not found in navbar"
    
    return True, "Navbar is consistent"


def _check_css_loaded(html_content):
    """Check if shared CSS is loaded"""
    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('link', rel='stylesheet')
    
    for link in links:
        href = link.get('href', '')
        if 'style.css' in href:
            return True, "Shared CSS loaded"
    
    return False, "Shared CSS not found"


class TestDashboardPages:
    """Test dashboard page accessibility and consistency"""
    
    def test_dashboard_root_accessible(self):
        """Test main dashboard page is accessible"""
        resp = _get("/")
        if resp is None:
            pytest.skip("Dashboard not running at http://127.0.0.1:5001")
        assert resp.status_code == 200, "Dashboard root should return 200"
    
    def test_dashboard_has_navbar(self):
        """Test dashboard has consistent navbar"""
        resp = _get("/")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        is_consistent, msg = _check_navbar(resp.text)
        assert is_consistent, msg
    
    def test_dashboard_has_shared_css(self):
        """Test dashboard loads shared CSS"""
        resp = _get("/")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        has_css, msg = _check_css_loaded(resp.text)
        assert has_css, msg
    
    def test_info_page_accessible(self):
        """Test info page is accessible"""
        resp = _get("/info")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200, "Info page should return 200"
    
    def test_info_page_has_navbar(self):
        """Test info page has consistent navbar"""
        resp = _get("/info")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        is_consistent, msg = _check_navbar(resp.text)
        assert is_consistent, msg
    
    def test_attacks_page_accessible(self):
        """Test attacks page is accessible"""
        resp = _get("/attacks")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200, "Attacks page should return 200"
    
    def test_attacks_page_has_navbar(self):
        """Test attacks page has consistent navbar"""
        resp = _get("/attacks")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        is_consistent, msg = _check_navbar(resp.text)
        assert is_consistent, msg
    
    def test_success_page_accessible(self):
        """Test success page is accessible"""
        resp = _get("/success")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200, "Success page should return 200"
    
    def test_success_page_has_navbar(self):
        """Test success page has consistent navbar"""
        resp = _get("/success")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        is_consistent, msg = _check_navbar(resp.text)
        assert is_consistent, msg
    
    def test_error_page_accessible(self):
        """Test error page is accessible"""
        resp = _get("/error")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200, "Error page should return 200"
    
    def test_error_page_has_navbar(self):
        """Test error page has consistent navbar"""
        resp = _get("/error")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        
        is_consistent, msg = _check_navbar(resp.text)
        assert is_consistent, msg
    
    def test_all_pages_have_shared_css(self):
        """Test all pages load shared CSS"""
        pages = ["/", "/info", "/attacks", "/success", "/error"]
        
        for page in pages:
            resp = _get(page)
            if resp is None:
                pytest.skip("Dashboard not running")
            
            assert resp.status_code == 200, f"Page {page} should return 200"
            has_css, msg = _check_css_loaded(resp.text)
            assert has_css, f"Page {page}: {msg}"
    
    def test_navbar_links_work(self):
        """Test that navbar links navigate correctly"""
        pages = ["/", "/info", "/attacks"]
        
        for page in pages:
            resp = _get(page)
            if resp is None:
                pytest.skip("Dashboard not running")
            
            assert resp.status_code == 200, f"Page {page} should be accessible"
            
            soup = BeautifulSoup(resp.text, 'html.parser')
            navbar = soup.find('nav', class_='navbar')
            links = navbar.find_all('a', class_='nav-link')
            
            for link in links:
                href = link.get('href')
                if href and href.startswith('/'):
                    link_resp = _get(href)
                    if link_resp is None:
                        pytest.skip("Dashboard not running")
                    assert link_resp.status_code == 200, f"Link {href} should be accessible"


class TestAPIEndpoints:
    """Test API endpoints"""
    
    def test_api_stats_endpoint(self):
        """Test stats API endpoint"""
        resp = _get("/api/stats")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
    
    def test_api_recent_connections(self):
        """Test recent connections API endpoint"""
        resp = _get("/api/recent-connections")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        data = resp.json()
        assert "connections" in data
        assert isinstance(data["connections"], list)
    
    def test_api_alerts(self):
        """Test alerts API endpoint"""
        resp = _get("/api/alerts")
        if resp is None:
            pytest.skip("Dashboard not running")
        assert resp.status_code == 200
        data = resp.json()
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

