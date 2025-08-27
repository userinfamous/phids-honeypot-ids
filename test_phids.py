#!/usr/bin/env python3
"""
Test script for PHIDS components
"""
import asyncio
import sys
import logging
from pathlib import Path
import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from src.core.database import DatabaseManager
from src.core.logger import setup_logging
from src.honeypots.ssh_honeypot import SSHHoneypot
from src.honeypots.http_honeypot import HTTPHoneypot
from src.ids.signatures import SignatureEngine
from src.analysis.ioc_extractor import IOCExtractor
from src.threat_intel.threat_intelligence import ThreatIntelligenceManager


@pytest.mark.asyncio
async def test_database():
    """Test database functionality"""
    print("Testing database...")
    try:
        db = DatabaseManager()
        await db.initialize()
        
        # Test connection logging
        test_connection = {
            'source_ip': '192.168.1.100',
            'source_port': 12345,
            'destination_port': 2222,
            'service_type': 'ssh',
            'session_id': 'test-session',
            'commands': ['whoami', 'ls -la'],
            'payloads': [],
            'user_agent': 'test-agent'
        }
        
        await db.log_connection(test_connection)
        
        # Test alert logging
        test_alert = {
            'alert_type': 'test_alert',
            'severity': 'medium',
            'source_ip': '192.168.1.100',
            'destination_ip': 'honeypot',
            'description': 'Test alert for verification'
        }
        
        await db.log_alert(test_alert)
        
        print("✓ Database test passed")

    except Exception as e:
        print(f"✗ Database test failed: {e}")
        pytest.fail(f"Database test failed: {e}")


def test_signature_engine():
    """Test signature detection engine"""
    print("Testing signature engine...")
    try:
        engine = SignatureEngine()
        
        # Test SQL injection detection
        test_data = {
            'source_ip': '192.168.1.100',
            'service_type': 'http',
            'commands': [{'path': '/login?user=admin\' OR 1=1--'}],
            'payloads': [],
            'user_agent': 'test-agent'
        }
        
        alerts = engine.analyze_connection(test_data)
        
        if alerts:
            print(f"✓ Signature engine detected {len(alerts)} alerts")
            for alert in alerts:
                print(f"  - {alert['name']}: {alert['description']}")
        else:
            print("✗ Signature engine failed to detect test attack")
            pytest.fail("Signature engine failed to detect test attack")

    except Exception as e:
        print(f"✗ Signature engine test failed: {e}")
        pytest.fail(f"Signature engine test failed: {e}")


def test_ioc_extractor():
    """Test IOC extraction"""
    print("Testing IOC extractor...")
    try:
        extractor = IOCExtractor()
        
        test_data = """
        GET /admin HTTP/1.1
        Host: 192.168.1.1
        User-Agent: sqlmap/1.0
        
        POST /login HTTP/1.1
        Content-Type: application/x-www-form-urlencoded
        
        username=admin' OR 1=1--&password=test
        """
        
        iocs = extractor.extract_iocs(test_data, "test")
        
        print(f"✓ IOC extractor found:")
        print(f"  - IP addresses: {len(iocs['ip_addresses'])}")
        print(f"  - Attack patterns: {len(iocs['attack_patterns'])}")
        print(f"  - User agents: {len(iocs['user_agents'])}")
        print(f"  - Risk score: {iocs['metadata']['risk_score']}")

    except Exception as e:
        print(f"✗ IOC extractor test failed: {e}")
        pytest.fail(f"IOC extractor test failed: {e}")


def test_honeypot_config():
    """Test honeypot configuration"""
    print("Testing honeypot configuration...")
    try:
        ssh_honeypot = SSHHoneypot()
        http_honeypot = HTTPHoneypot()
        
        print(f"✓ SSH Honeypot enabled: {ssh_honeypot.is_enabled()}")
        print(f"✓ HTTP Honeypot enabled: {http_honeypot.is_enabled()}")

    except Exception as e:
        print(f"✗ Honeypot configuration test failed: {e}")
        pytest.fail(f"Honeypot configuration test failed: {e}")


@pytest.mark.asyncio
async def test_threat_intelligence():
    """Test threat intelligence (without API calls)"""
    print("Testing threat intelligence...")
    try:
        ti_manager = ThreatIntelligenceManager()
        
        # Test configuration
        stats = ti_manager.get_statistics()
        print(f"✓ Threat intelligence configured:")
        print(f"  - VirusTotal enabled: {stats['services_enabled']['virustotal']}")
        print(f"  - AbuseIPDB enabled: {stats['services_enabled']['abuseipdb']}")

    except Exception as e:
        print(f"✗ Threat intelligence test failed: {e}")
        pytest.fail(f"Threat intelligence test failed: {e}")


async def run_tests():
    """Run all tests"""
    print("=" * 50)
    print("PHIDS Component Tests")
    print("=" * 50)
    
    # Setup logging
    setup_logging("INFO")
    
    tests = [
        ("Database", test_database()),
        ("Signature Engine", test_signature_engine()),
        ("IOC Extractor", test_ioc_extractor()),
        ("Honeypot Config", test_honeypot_config()),
        ("Threat Intelligence", test_threat_intelligence())
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        if asyncio.iscoroutine(test_func):
            result = await test_func
        else:
            result = test_func
        results.append((test_name, result))
    
    print("\n" + "=" * 50)
    print("Test Results Summary:")
    print("=" * 50)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! PHIDS is ready to run.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the configuration.")
        return False


if __name__ == "__main__":
    success = asyncio.run(run_tests())
    sys.exit(0 if success else 1)
