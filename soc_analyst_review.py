#!/usr/bin/env python3
"""
SOC Analyst Perspective Review for PHIDS
Evaluates system from professional cybersecurity analyst viewpoint
"""

import requests
import json
import time
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import sys

class SOCAnalystReview:
    def __init__(self):
        self.db_path = Path("data/phids.db")
        self.dashboard_url = "http://127.0.0.1:5001"
        self.http_honeypot_url = "http://127.0.0.1:8081"
        self.ssh_honeypot_port = 2222
        self.findings = []
        self.recommendations = []
        
    def log_finding(self, category, severity, title, description, recommendation=""):
        """Log a SOC analyst finding"""
        finding = {
            "category": category,
            "severity": severity,  # CRITICAL, HIGH, MEDIUM, LOW, INFO
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        severity_icon = {
            "CRITICAL": "🔴",
            "HIGH": "🟠", 
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "ℹ️"
        }
        
        print(f"{severity_icon.get(severity, '❓')} {severity} - {category}: {title}")
        print(f"   {description}")
        if recommendation:
            print(f"   💡 Recommendation: {recommendation}")
        print()
    
    def evaluate_detection_capabilities(self):
        """Evaluate attack detection capabilities"""
        print("🔍 Evaluating Detection Capabilities...")
        
        # Test SQL injection detection
        try:
            response = requests.get(f"{self.http_honeypot_url}/login?user=admin&pass=admin' OR '1'='1", timeout=5)
            time.sleep(1)  # Allow processing time
            
            # Check if alert was generated
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT COUNT(*) FROM ids_alerts 
                WHERE description LIKE '%injection%' 
                AND timestamp >= datetime('now', '-1 minute')
            """)
            sql_alerts = cursor.fetchone()[0]
            conn.close()
            
            if sql_alerts > 0:
                self.log_finding("Detection", "INFO", "SQL Injection Detection", 
                               "System successfully detects SQL injection attempts",
                               "Continue monitoring for advanced evasion techniques")
            else:
                self.log_finding("Detection", "HIGH", "SQL Injection Detection Gap", 
                               "SQL injection attempt not detected by IDS",
                               "Review and enhance SQL injection detection rules")
                
        except Exception as e:
            self.log_finding("Detection", "MEDIUM", "Detection Test Error", 
                           f"Could not test SQL injection detection: {e}",
                           "Verify honeypot connectivity and IDS functionality")
    
    def evaluate_response_times(self):
        """Evaluate system response times for SOC operations"""
        print("⚡ Evaluating Response Times...")
        
        # Test dashboard API response time
        start_time = time.time()
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=10)
            api_response_time = time.time() - start_time
            
            if api_response_time < 0.5:
                self.log_finding("Performance", "INFO", "Dashboard API Performance", 
                               f"API responds in {api_response_time:.3f}s - excellent for SOC operations")
            elif api_response_time < 2.0:
                self.log_finding("Performance", "LOW", "Dashboard API Performance", 
                               f"API responds in {api_response_time:.3f}s - acceptable for SOC operations")
            else:
                self.log_finding("Performance", "MEDIUM", "Dashboard API Performance", 
                               f"API responds in {api_response_time:.3f}s - may impact SOC efficiency",
                               "Optimize database queries and caching")
                
        except Exception as e:
            self.log_finding("Performance", "HIGH", "Dashboard API Unavailable", 
                           f"Cannot access dashboard API: {e}",
                           "Verify dashboard service is running and accessible")
    
    def evaluate_data_quality(self):
        """Evaluate data quality for forensic analysis"""
        print("📊 Evaluating Data Quality...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Check for complete connection records
            cursor = conn.execute("""
                SELECT COUNT(*) as total,
                       COUNT(source_ip) as has_source_ip,
                       COUNT(timestamp) as has_timestamp,
                       COUNT(service_type) as has_service_type
                FROM honeypot_connections
                WHERE timestamp >= datetime('now', '-24 hours')
            """)
            
            row = cursor.fetchone()
            total, has_source_ip, has_timestamp, has_service_type = row
            
            if total > 0:
                completeness = min(has_source_ip, has_timestamp, has_service_type) / total * 100
                
                if completeness >= 95:
                    self.log_finding("Data Quality", "INFO", "Connection Data Completeness", 
                                   f"Data completeness: {completeness:.1f}% - excellent for forensics")
                elif completeness >= 80:
                    self.log_finding("Data Quality", "LOW", "Connection Data Completeness", 
                                   f"Data completeness: {completeness:.1f}% - good but could be improved")
                else:
                    self.log_finding("Data Quality", "MEDIUM", "Connection Data Completeness", 
                                   f"Data completeness: {completeness:.1f}% - insufficient for reliable forensics",
                                   "Review data collection processes and fix missing fields")
            
            # Check timestamp precision
            cursor = conn.execute("""
                SELECT timestamp FROM honeypot_connections 
                ORDER BY id DESC LIMIT 10
            """)
            
            timestamps = [row[0] for row in cursor.fetchall()]
            iso_format_count = 0
            
            for ts in timestamps:
                try:
                    datetime.fromisoformat(ts)
                    iso_format_count += 1
                except:
                    pass
            
            if len(timestamps) > 0:
                format_compliance = iso_format_count / len(timestamps) * 100
                
                if format_compliance == 100:
                    self.log_finding("Data Quality", "INFO", "Timestamp Format Compliance", 
                                   "All timestamps use ISO 8601 format - excellent for analysis")
                else:
                    self.log_finding("Data Quality", "MEDIUM", "Timestamp Format Compliance", 
                                   f"Only {format_compliance:.1f}% timestamps use ISO 8601 format",
                                   "Standardize all timestamp formats to ISO 8601")
            
            conn.close()
            
        except Exception as e:
            self.log_finding("Data Quality", "HIGH", "Database Access Error", 
                           f"Cannot access database for quality assessment: {e}",
                           "Verify database integrity and permissions")
    
    def evaluate_threat_intelligence(self):
        """Evaluate threat intelligence capabilities"""
        print("🌐 Evaluating Threat Intelligence...")
        
        try:
            # Check if threat intelligence data exists
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM threat_intelligence")
            ti_count = cursor.fetchone()[0]
            
            if ti_count > 0:
                self.log_finding("Threat Intelligence", "INFO", "Threat Intelligence Data", 
                               f"System contains {ti_count} threat intelligence records")
            else:
                self.log_finding("Threat Intelligence", "MEDIUM", "Limited Threat Intelligence", 
                               "No threat intelligence data found",
                               "Integrate with threat intelligence feeds (VirusTotal, AbuseIPDB)")
            
            # Check geolocation capabilities
            response = requests.get(f"{self.dashboard_url}/api/recent-connections", timeout=5)
            if response.status_code == 200:
                connections = response.json().get("connections", [])
                if connections:
                    # Check if connections have geolocation data
                    has_geo = any("country" in str(conn) for conn in connections[:5])
                    
                    if has_geo:
                        self.log_finding("Threat Intelligence", "INFO", "Geolocation Capability", 
                                       "System provides IP geolocation for attack attribution")
                    else:
                        self.log_finding("Threat Intelligence", "LOW", "Limited Geolocation", 
                                       "Geolocation data not readily available",
                                       "Enhance IP geolocation for better attack attribution")
            
            conn.close()
            
        except Exception as e:
            self.log_finding("Threat Intelligence", "MEDIUM", "Threat Intelligence Assessment Error", 
                           f"Could not assess threat intelligence: {e}")
    
    def evaluate_alerting_system(self):
        """Evaluate alerting and notification capabilities"""
        print("🚨 Evaluating Alerting System...")
        
        try:
            # Check recent alerts
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM ids_alerts 
                WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY severity
            """)
            
            alert_summary = dict(cursor.fetchall())
            total_alerts = sum(alert_summary.values())
            
            if total_alerts > 0:
                self.log_finding("Alerting", "INFO", "Alert Generation", 
                               f"Generated {total_alerts} alerts in last 24h: {alert_summary}")
                
                # Check alert severity distribution
                critical_high = alert_summary.get('critical', 0) + alert_summary.get('high', 0)
                if critical_high / total_alerts > 0.8:
                    self.log_finding("Alerting", "MEDIUM", "High Alert Volume", 
                                   f"{critical_high}/{total_alerts} alerts are critical/high severity",
                                   "Review alert thresholds to reduce false positives")
            else:
                self.log_finding("Alerting", "LOW", "No Recent Alerts", 
                               "No alerts generated in last 24 hours",
                               "Verify IDS rules are active and properly configured")
            
            conn.close()
            
        except Exception as e:
            self.log_finding("Alerting", "MEDIUM", "Alert Assessment Error", 
                           f"Could not assess alerting system: {e}")
    
    def evaluate_export_capabilities(self):
        """Evaluate data export capabilities for SIEM integration"""
        print("📤 Evaluating Export Capabilities...")
        
        try:
            # Test CSV export
            response = requests.get(f"{self.dashboard_url}/api/export/connections?format=csv", timeout=10)
            
            if response.status_code == 200:
                self.log_finding("Export", "INFO", "CSV Export Capability", 
                               "System supports CSV export for SIEM integration")
            else:
                self.log_finding("Export", "MEDIUM", "Limited Export Capability", 
                               f"CSV export returned status {response.status_code}",
                               "Implement robust data export for SIEM integration")
                
        except Exception as e:
            self.log_finding("Export", "MEDIUM", "Export Test Error", 
                           f"Could not test export capabilities: {e}")
    
    def generate_soc_recommendations(self):
        """Generate SOC-specific recommendations"""
        print("💡 Generating SOC Recommendations...")
        
        # Analyze findings and generate recommendations
        critical_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        high_count = sum(1 for f in self.findings if f["severity"] == "HIGH")
        
        if critical_count > 0:
            self.recommendations.append({
                "priority": "IMMEDIATE",
                "title": "Address Critical Issues",
                "description": f"Resolve {critical_count} critical findings before production deployment"
            })
        
        if high_count > 0:
            self.recommendations.append({
                "priority": "HIGH",
                "title": "Address High Priority Issues", 
                "description": f"Resolve {high_count} high priority findings within 48 hours"
            })
        
        # SOC-specific recommendations
        self.recommendations.extend([
            {
                "priority": "MEDIUM",
                "title": "Implement SIEM Integration",
                "description": "Configure automated log forwarding to enterprise SIEM platform"
            },
            {
                "priority": "MEDIUM", 
                "title": "Establish Incident Response Procedures",
                "description": "Create playbooks for common attack scenarios detected by honeypots"
            },
            {
                "priority": "LOW",
                "title": "Regular Threat Intelligence Updates",
                "description": "Schedule automated updates of threat intelligence feeds"
            },
            {
                "priority": "LOW",
                "title": "Performance Monitoring",
                "description": "Implement monitoring for system performance and availability"
            }
        ])
    
    def run_comprehensive_review(self):
        """Run comprehensive SOC analyst review"""
        print("🛡️ PHIDS SOC Analyst Review")
        print("=" * 50)
        print("Evaluating system from professional cybersecurity analyst perspective...")
        print()
        
        # Check if PHIDS is running
        try:
            response = requests.get(f"{self.dashboard_url}/api/stats", timeout=5)
            if response.status_code != 200:
                print("❌ PHIDS dashboard not accessible. Please start PHIDS first.")
                return False
        except:
            print("❌ PHIDS not running. Please start with: python main.py --debug")
            return False
        
        # Run evaluations
        self.evaluate_detection_capabilities()
        self.evaluate_response_times()
        self.evaluate_data_quality()
        self.evaluate_threat_intelligence()
        self.evaluate_alerting_system()
        self.evaluate_export_capabilities()
        
        # Generate recommendations
        self.generate_soc_recommendations()
        
        # Summary
        print("=" * 50)
        print("📋 SOC Analyst Review Summary")
        print("=" * 50)
        
        severity_counts = {}
        for finding in self.findings:
            severity = finding["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("Findings by Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity}: {count}")
        
        print(f"\nTotal Findings: {len(self.findings)}")
        print(f"Recommendations: {len(self.recommendations)}")
        
        # Overall assessment
        critical_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0)
        
        if critical_high == 0:
            print("\n✅ PHIDS is ready for SOC deployment with minor improvements")
        elif critical_high <= 2:
            print("\n⚠️ PHIDS requires some improvements before SOC deployment")
        else:
            print("\n🔴 PHIDS requires significant improvements before SOC deployment")
        
        # Save detailed report
        report = {
            "review_timestamp": datetime.now().isoformat(),
            "findings": self.findings,
            "recommendations": self.recommendations,
            "summary": {
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
                "critical_high_count": critical_high
            }
        }
        
        with open("soc_analyst_review.json", "w") as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Detailed review saved to: soc_analyst_review.json")
        return critical_high == 0

if __name__ == "__main__":
    reviewer = SOCAnalystReview()
    success = reviewer.run_comprehensive_review()
    sys.exit(0 if success else 1)
