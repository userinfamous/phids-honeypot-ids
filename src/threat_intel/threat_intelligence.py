"""
Threat Intelligence integration for PHIDS
"""
import asyncio
import aiohttp
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from config import THREAT_INTEL_CONFIG
from src.core.database import DatabaseManager


class ThreatIntelligenceManager:
    """Manage threat intelligence lookups and enrichment"""
    
    def __init__(self):
        self.logger = logging.getLogger("threat_intel")
        self.db_manager = DatabaseManager()
        self.config = THREAT_INTEL_CONFIG
        
        # Rate limiting
        self.rate_limits = {
            'virustotal': {
                'requests': 0,
                'reset_time': time.time() + 60,
                'limit': self.config['virustotal']['rate_limit']
            },
            'abuseipdb': {
                'requests': 0,
                'reset_time': time.time() + 86400,  # 24 hours
                'limit': self.config['abuseipdb']['rate_limit']
            }
        }
        
        # Cache for recent lookups
        self.lookup_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    async def enrich_ip(self, ip_address: str) -> Dict:
        """Enrich IP address with threat intelligence"""
        self.logger.debug(f"Enriching IP: {ip_address}")
        
        # Check cache first
        cache_key = f"ip_{ip_address}"
        if self._is_cached(cache_key):
            return self.lookup_cache[cache_key]['data']
        
        enrichment_data = {
            'ip_address': ip_address,
            'last_updated': datetime.now(),
            'reputation_score': 0,
            'is_malicious': False,
            'threat_types': [],
            'sources': {}
        }
        
        # VirusTotal lookup
        if self.config['virustotal']['enabled']:
            vt_data = await self._virustotal_ip_lookup(ip_address)
            if vt_data:
                enrichment_data['sources']['virustotal'] = vt_data
                enrichment_data = self._process_virustotal_data(enrichment_data, vt_data)
        
        # AbuseIPDB lookup
        if self.config['abuseipdb']['enabled']:
            abuse_data = await self._abuseipdb_lookup(ip_address)
            if abuse_data:
                enrichment_data['sources']['abuseipdb'] = abuse_data
                enrichment_data = self._process_abuseipdb_data(enrichment_data, abuse_data)
        
        # WHOIS lookup (basic)
        whois_data = await self._basic_whois_lookup(ip_address)
        if whois_data:
            enrichment_data['sources']['whois'] = whois_data
            enrichment_data = self._process_whois_data(enrichment_data, whois_data)
        
        # Cache the result
        self._cache_result(cache_key, enrichment_data)
        
        # Store in database
        await self._store_threat_intel(enrichment_data)
        
        return enrichment_data
    
    async def _virustotal_ip_lookup(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP in VirusTotal"""
        if not self._check_rate_limit('virustotal'):
            self.logger.warning("VirusTotal rate limit exceeded")
            return None
        
        api_key = self.config['virustotal']['api_key']
        if not api_key:
            self.logger.warning("VirusTotal API key not configured")
            return None
        
        url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
        params = {
            'apikey': api_key,
            'ip': ip_address
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._update_rate_limit('virustotal')
                        return data
                    else:
                        self.logger.error(f"VirusTotal API error: {response.status}")
                        return None
        
        except Exception as e:
            self.logger.error(f"VirusTotal lookup error: {e}")
            return None
    
    async def _abuseipdb_lookup(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP in AbuseIPDB"""
        if not self._check_rate_limit('abuseipdb'):
            self.logger.warning("AbuseIPDB rate limit exceeded")
            return None
        
        api_key = self.config['abuseipdb']['api_key']
        if not api_key:
            self.logger.warning("AbuseIPDB API key not configured")
            return None
        
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._update_rate_limit('abuseipdb')
                        return data
                    else:
                        self.logger.error(f"AbuseIPDB API error: {response.status}")
                        return None
        
        except Exception as e:
            self.logger.error(f"AbuseIPDB lookup error: {e}")
            return None
    
    async def _basic_whois_lookup(self, ip_address: str) -> Optional[Dict]:
        """Basic WHOIS lookup (simplified)"""
        try:
            # In a real implementation, you would use a proper WHOIS library
            # For now, we'll return a placeholder
            return {
                'country': 'Unknown',
                'asn': 'Unknown',
                'organization': 'Unknown',
                'lookup_time': datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"WHOIS lookup error: {e}")
            return None
    
    def _process_virustotal_data(self, enrichment_data: Dict, vt_data: Dict) -> Dict:
        """Process VirusTotal response data"""
        try:
            if vt_data.get('response_code') == 1:
                # Extract detection information
                detected_urls = vt_data.get('detected_urls', [])
                detected_samples = vt_data.get('detected_communicating_samples', [])
                
                # Calculate reputation score
                if detected_urls or detected_samples:
                    enrichment_data['is_malicious'] = True
                    enrichment_data['reputation_score'] += 50
                    enrichment_data['threat_types'].append('malware_communication')
                
                # Extract country information
                if 'country' in vt_data:
                    enrichment_data['country'] = vt_data['country']
                
                # Extract ASN information
                if 'asn' in vt_data:
                    enrichment_data['asn'] = str(vt_data['asn'])
        
        except Exception as e:
            self.logger.error(f"Error processing VirusTotal data: {e}")
        
        return enrichment_data
    
    def _process_abuseipdb_data(self, enrichment_data: Dict, abuse_data: Dict) -> Dict:
        """Process AbuseIPDB response data"""
        try:
            data = abuse_data.get('data', {})
            
            # Extract abuse confidence
            abuse_confidence = data.get('abuseConfidencePercentage', 0)
            if abuse_confidence > 0:
                enrichment_data['reputation_score'] += abuse_confidence
                
                if abuse_confidence > 75:
                    enrichment_data['is_malicious'] = True
                    enrichment_data['threat_types'].append('high_abuse_confidence')
            
            # Extract usage type
            usage_type = data.get('usageType')
            if usage_type:
                enrichment_data['usage_type'] = usage_type
            
            # Extract country
            country_code = data.get('countryCode')
            if country_code:
                enrichment_data['country'] = country_code
            
            # Extract ISP
            isp = data.get('isp')
            if isp:
                enrichment_data['isp'] = isp
        
        except Exception as e:
            self.logger.error(f"Error processing AbuseIPDB data: {e}")
        
        return enrichment_data
    
    def _process_whois_data(self, enrichment_data: Dict, whois_data: Dict) -> Dict:
        """Process WHOIS data"""
        try:
            if 'country' in whois_data and not enrichment_data.get('country'):
                enrichment_data['country'] = whois_data['country']
            
            if 'asn' in whois_data and not enrichment_data.get('asn'):
                enrichment_data['asn'] = whois_data['asn']
            
            if 'organization' in whois_data:
                enrichment_data['organization'] = whois_data['organization']
        
        except Exception as e:
            self.logger.error(f"Error processing WHOIS data: {e}")
        
        return enrichment_data
    
    def _check_rate_limit(self, service: str) -> bool:
        """Check if service is within rate limits"""
        current_time = time.time()
        rate_limit = self.rate_limits[service]
        
        # Reset counter if time window has passed
        if current_time > rate_limit['reset_time']:
            rate_limit['requests'] = 0
            if service == 'virustotal':
                rate_limit['reset_time'] = current_time + 60  # 1 minute
            else:  # abuseipdb
                rate_limit['reset_time'] = current_time + 86400  # 24 hours
        
        return rate_limit['requests'] < rate_limit['limit']
    
    def _update_rate_limit(self, service: str):
        """Update rate limit counter"""
        self.rate_limits[service]['requests'] += 1
    
    def _is_cached(self, cache_key: str) -> bool:
        """Check if result is cached and still valid"""
        if cache_key not in self.lookup_cache:
            return False
        
        cache_entry = self.lookup_cache[cache_key]
        return time.time() - cache_entry['timestamp'] < self.cache_ttl
    
    def _cache_result(self, cache_key: str, data: Dict):
        """Cache lookup result"""
        self.lookup_cache[cache_key] = {
            'timestamp': time.time(),
            'data': data
        }
        
        # Clean old cache entries
        current_time = time.time()
        expired_keys = [
            key for key, entry in self.lookup_cache.items()
            if current_time - entry['timestamp'] > self.cache_ttl
        ]
        
        for key in expired_keys:
            del self.lookup_cache[key]
    
    async def _store_threat_intel(self, enrichment_data: Dict):
        """Store threat intelligence in database"""
        try:
            ip_data = {
                'ip_address': enrichment_data['ip_address'],
                'reputation_score': min(enrichment_data['reputation_score'], 100),
                'country': enrichment_data.get('country', 'Unknown'),
                'asn': enrichment_data.get('asn', 'Unknown'),
                'is_malicious': enrichment_data['is_malicious'],
                'threat_types': enrichment_data['threat_types'],
                'virustotal_data': enrichment_data['sources'].get('virustotal', {}),
                'abuseipdb_data': enrichment_data['sources'].get('abuseipdb', {}),
                'whois_data': enrichment_data['sources'].get('whois', {})
            }
            
            await self.db_manager.update_threat_intelligence(ip_data)
            
        except Exception as e:
            self.logger.error(f"Error storing threat intelligence: {e}")
    
    async def bulk_enrich_ips(self, ip_addresses: List[str]) -> Dict[str, Dict]:
        """Enrich multiple IP addresses"""
        results = {}
        
        for ip in ip_addresses:
            try:
                enrichment = await self.enrich_ip(ip)
                results[ip] = enrichment
                
                # Add delay to respect rate limits
                await asyncio.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Error enriching IP {ip}: {e}")
                results[ip] = {'error': str(e)}
        
        return results
    
    async def get_cached_intelligence(self, ip_address: str) -> Optional[Dict]:
        """Get cached threat intelligence for IP"""
        cache_key = f"ip_{ip_address}"
        if self._is_cached(cache_key):
            return self.lookup_cache[cache_key]['data']
        return None
    
    def get_statistics(self) -> Dict:
        """Get threat intelligence statistics"""
        return {
            'cache_size': len(self.lookup_cache),
            'rate_limits': {
                service: {
                    'requests_used': limits['requests'],
                    'limit': limits['limit'],
                    'reset_time': limits['reset_time']
                }
                for service, limits in self.rate_limits.items()
            },
            'services_enabled': {
                'virustotal': self.config['virustotal']['enabled'],
                'abuseipdb': self.config['abuseipdb']['enabled']
            }
        }
    
    def clear_cache(self):
        """Clear threat intelligence cache"""
        self.lookup_cache.clear()
        self.logger.info("Threat intelligence cache cleared")
