"""
Data fetching modules for security assessment
"""
import requests
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import time

logger = logging.getLogger(__name__)


class ProductHuntAPI:
    """Fetch product information from ProductHunt API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.producthunt.com/v2/api/graphql"
        
    def search_product(self, product_name: str) -> Optional[Dict[str, Any]]:
        """Search for a product on ProductHunt"""
        
        query = """
        query($term: String!) {
          posts(first: 5, postedAfter: "2020-01-01", order: VOTES) {
            edges {
              node {
                id
                name
                tagline
                description
                url
                website
                votesCount
                commentsCount
                createdAt
                productLinks {
                  url
                  type
                }
                topics {
                  edges {
                    node {
                      name
                    }
                  }
                }
                makers {
                  edges {
                    node {
                      name
                      url
                    }
                  }
                }
              }
            }
          }
        }
        """
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.post(
                self.base_url,
                json={"query": query, "variables": {"term": product_name}},
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                products = data.get('data', {}).get('posts', {}).get('edges', [])
                
                # Find best match
                for edge in products:
                    node = edge.get('node', {})
                    if product_name.lower() in node.get('name', '').lower():
                        return self._format_product_data(node)
                
                # Return first result if no exact match
                if products:
                    return self._format_product_data(products[0].get('node', {}))
                    
            logger.warning(f"ProductHunt API returned status {response.status_code}")
            return None
            
        except Exception as e:
            logger.error(f"Error fetching from ProductHunt: {e}")
            return None
    
    def _format_product_data(self, node: Dict) -> Dict[str, Any]:
        """Format ProductHunt data"""
        topics = [edge['node']['name'] for edge in node.get('topics', {}).get('edges', [])]
        makers = [edge['node']['name'] for edge in node.get('makers', {}).get('edges', [])]
        
        return {
            "name": node.get('name'),
            "tagline": node.get('tagline'),
            "description": node.get('description'),
            "url": node.get('url'),
            "website": node.get('website'),
            "votes": node.get('votesCount', 0),
            "comments": node.get('commentsCount', 0),
            "created_at": node.get('createdAt'),
            "topics": topics,
            "makers": makers,
            "source": "ProductHunt",
            "source_type": "mixed"  # ProductHunt contains both vendor-provided and community data
        }


class NVDAPI:
    """Fetch CVE information from NVD (National Vulnerability Database) API 2.0"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key
        self.headers = {}
        
        if api_key:
            self.headers["apiKey"] = api_key
            logger.info("NVD API initialized with API key (higher rate limits)")
        else:
            logger.warning("NVD API key not provided - rate limited to 5 requests per 30 seconds")
        
        self.last_request_time = 0
        self.rate_limit_delay = 6 if not api_key else 0.6  # 6 seconds without key, 0.6 with key
        
    def _rate_limit(self):
        """Enforce rate limiting"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def search_cves(self, vendor: str, product: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Search for CVEs by vendor and optionally product using NVD keyword search"""
        
        all_cves = []
        start_index = 0
        
        # Clean vendor and product names
        clean_vendor = self._extract_vendor_keyword(vendor)
        clean_product = self._extract_vendor_keyword(product) if product else None
        
        # Use keyword search (more reliable than CPE matching with wildcards)
        if clean_product:
            keyword = clean_product
            logger.info(f"Searching NVD for product: {clean_product}")
        else:
            keyword = clean_vendor
            logger.info(f"Searching NVD for vendor: {clean_vendor}")
        
        # Fetch CVEs in pages
        while len(all_cves) < limit:
            self._rate_limit()
            
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": min(50, limit - len(all_cves)),
                "startIndex": start_index
            }
            
            response = requests.get(self.base_url, params=params, headers=self.headers, timeout=30)
            
            if response.status_code != 200:
                logger.warning(f"NVD API returned status {response.status_code}")
                break
            
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            if not vulnerabilities:
                break
            
            for vuln_item in vulnerabilities:
                all_cves.append(self._format_cve_data(vuln_item['cve']))
            
            if start_index + len(vulnerabilities) >= data.get('totalResults', 0):
                break
            
            start_index += len(vulnerabilities)
        
        all_cves.sort(key=lambda x: x['published_date'], reverse=True)
        return all_cves[:limit]
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE"""
        
        self._rate_limit()
        
        response = requests.get(
            self.base_url,
            params={"cveId": cve_id},
            headers=self.headers,
            timeout=15
        )
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            if vulnerabilities:
                return self._format_cve_data(vulnerabilities[0]['cve'])
        
        return None
    
    def _extract_vendor_keyword(self, name: str) -> str:
        """Extract the core vendor/product keyword from a full company name"""
        if not name:
            return ""
        
        name_lower = name.lower().strip()
        
        # List of common suffixes to remove
        suffixes_to_remove = [
            ' inc.', ' inc', ' incorporated',
            ' llc', ' ltd', ' ltd.',
            ' corporation', ' corp', ' corp.',
            ' company', ' co', ' co.',
            ' limited',
            ' labs',
            ' technologies', ' technology', ' tech',
            ' software',
            ' systems',
            ' solutions',
            ' group',
            ' international',
            ' enterprises',
            ' holdings'
        ]
        
        # Remove suffixes
        for suffix in suffixes_to_remove:
            if name_lower.endswith(suffix):
                name_lower = name_lower[:-len(suffix)].strip()
                break  # Only remove one suffix
        
        # Remove common prefixes
        prefixes_to_remove = ['the ']
        for prefix in prefixes_to_remove:
            if name_lower.startswith(prefix):
                name_lower = name_lower[len(prefix):].strip()
        
        # Take the first word if multiple words remain (e.g., "notion labs" -> "notion")
        words = name_lower.split()
        if len(words) > 1:
            # Keep first word unless it's very generic
            generic_words = ['open', 'free', 'gnu', 'apache']
            if words[0] not in generic_words:
                return words[0]
        
        return name_lower
    
    def _format_cve_data(self, cve: Dict) -> Dict[str, Any]:
        """Format CVE data from NVD API 2.0 response"""
        
        # Required fields - cve object always has 'id'
        cve_id = cve['id']
        published_date = cve['published']
        updated_date = cve['lastModified']
        
        # descriptions is required - get English description
        summary = next((d['value'] for d in cve['descriptions'] if d.get('lang') == 'en'), '')
        
        # metrics is optional
        metrics = cve.get('metrics', {})
        cvss_score = None
        cvss_vector = None
        severity = None
        
        # Try v3.1, then v3.0, then v2.0
        for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0]['cvssData']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = cvss_data['baseSeverity'].upper()
                break
        
        if not cvss_score:
            metric_list = metrics.get('cvssMetricV2', [])
            if metric_list:
                cvss_data = metric_list[0]['cvssData']
                cvss_score = cvss_data['baseScore']
                cvss_vector = cvss_data['vectorString']
                severity = "HIGH" if cvss_score >= 7.0 else "MEDIUM" if cvss_score >= 4.0 else "LOW"
        
        # weaknesses is optional
        cwes = [desc['value'] for weakness in cve.get('weaknesses', []) 
                for desc in weakness.get('description', []) 
                if desc.get('value', '').startswith('CWE-')]
        
        # configurations is optional
        vendors = set()
        products = set()
        for config in cve.get('configurations', []):
            for node in config.get('nodes', []):
                for cpe_match in node.get('cpeMatch', []):
                    parts = cpe_match.get('criteria', '').split(':')
                    if len(parts) >= 5:
                        vendors.add(parts[3])
                        products.add(parts[4])
        
        return {
            "cve_id": cve_id,
            "summary": summary,
            "published_date": published_date,
            "updated_date": updated_date,
            "cvss_v3": cvss_score,
            "cvss_vector": cvss_vector,
            "severity": severity,
            "vendors": list(vendors),
            "products": list(products),
            "cwes": cwes,
            "source": "NVD",
            "source_type": "independent",
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        }



class CISAKEVAPI:
    """Fetch Known Exploited Vulnerabilities from CISA KEV catalog"""
    
    def __init__(self):
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self._cache = None
        self._cache_time = None
        self._cache_duration = 3600  # 1 hour
        
    def get_kev_catalog(self) -> Dict[str, Any]:
        """Fetch the entire KEV catalog"""
        
        # Use cache if available and fresh
        if self._cache and self._cache_time:
            if (datetime.now().timestamp() - self._cache_time) < self._cache_duration:
                return self._cache
        
        try:
            response = requests.get(self.kev_url, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                self._cache = data
                self._cache_time = datetime.now().timestamp()
                return data
            else:
                logger.warning(f"CISA KEV API returned status {response.status_code}")
                return {"vulnerabilities": []}
                
        except Exception as e:
            logger.error(f"Error fetching CISA KEV catalog: {e}")
            return {"vulnerabilities": []}
    
    def search_kev(self, vendor: str, product: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search KEV catalog for specific vendor/product"""
        
        catalog = self.get_kev_catalog()
        vulnerabilities = catalog.get('vulnerabilities', [])
        
        results = []
        
        # Extract keywords
        vendor_keywords = self._extract_keywords(vendor)
        product_keywords = self._extract_keywords(product) if product else []
        
        for vuln in vulnerabilities:
            vendor_project = vuln.get('vendorProject', '').lower()
            product_name = vuln.get('product', '').lower()
            
            # Check vendor match
            vendor_match = any(kw in vendor_project for kw in vendor_keywords)
            
            if vendor_match:
                # If product specified, must match product too
                if product_keywords:
                    product_match = any(kw in product_name for kw in product_keywords)
                    if product_match:
                        results.append(self._format_kev_data(vuln))
                else:
                    # No product filter, include all vendor matches
                    results.append(self._format_kev_data(vuln))
        
        return results
    
    def _extract_keywords(self, name: str) -> List[str]:
        """Extract search keywords from vendor/product name"""
        if not name:
            return []
        
        name_lower = name.lower().strip()
        
        # Remove common suffixes
        for suffix in [' inc', ' llc', ' ltd', ' corp', ' corporation', ' company', 
                       ' technologies', ' technology', ' software', ' labs']:
            if name_lower.endswith(suffix):
                name_lower = name_lower[:-len(suffix)].strip()
        
        # Split into words and filter out generic terms
        words = name_lower.split()
        generic = {'the', 'a', 'an', 'and', 'or', 'of', 'for', 'with'}
        return [w for w in words if w not in generic and len(w) > 2]
    
    def _format_kev_data(self, vuln: Dict) -> Dict[str, Any]:
        """Format KEV data according to CISA schema"""
        # Required fields per schema
        cve_id = vuln['cveID']
        return {
            "cve_id": cve_id,
            "vendor_project": vuln['vendorProject'],
            "product": vuln['product'],
            "vulnerability_name": vuln['vulnerabilityName'],
            "date_added": vuln['dateAdded'],
            "description": vuln['shortDescription'],
            "required_action": vuln['requiredAction'],
            "due_date": vuln['dueDate'],
            "known_ransomware": vuln.get('knownRansomwareCampaignUse'),
            "notes": vuln.get('notes', ''),
            "cwes": vuln.get('cwes', []),
            "source": "CISA KEV",
            "source_type": "independent",
            "source_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve_id}"
        }


class VirusTotalAPI:
    """Fetch file analysis information from VirusTotal API"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }
        
    def lookup_hash(self, sha1_hash: str) -> Optional[Dict[str, Any]]:
        """
        Look up a file by its SHA1 hash.
        
        Args:
            sha1_hash: The SHA1 hash of the file to look up
            
        Returns:
            Dictionary containing file analysis data or None if not found
        """
        sha1_hash = sha1_hash.strip().lower()
        
        try:
            # Look up file by hash
            url = f"{self.base_url}/files/{sha1_hash}"
            response = requests.get(url, headers=self.headers, timeout=15)
            
            if response.status_code == 200:
                data = response.json()
                return self._format_virustotal_data(data)
            elif response.status_code == 404:
                logger.warning(f"Hash {sha1_hash} not found in VirusTotal")
                return None
            else:
                logger.warning(f"VirusTotal API returned status {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"Error fetching from VirusTotal: {e}")
            return None
    
    def _format_virustotal_data(self, response_data: Dict) -> Dict[str, Any]:
        """Format VirusTotal API response data"""
        
        data = response_data.get('data', {})
        attributes = data.get('attributes', {})
        
        # Basic file information
        file_info = {
            "sha1": attributes.get('sha1', ''),
            "sha256": attributes.get('sha256', ''),
            "md5": attributes.get('md5', ''),
            "size": attributes.get('size', 0),
            "type": attributes.get('type_description', ''),
            "file_type": attributes.get('type_tag', ''),
        }
        
        # File names
        names = attributes.get('names', [])
        if names:
            file_info['names'] = names[:10]  # Limit to first 10 names
            file_info['primary_name'] = names[0]
        
        # Analysis statistics
        last_analysis = attributes.get('last_analysis_stats', {})
        file_info['detection_stats'] = {
            "malicious": last_analysis.get('malicious', 0),
            "suspicious": last_analysis.get('suspicious', 0),
            "undetected": last_analysis.get('undetected', 0),
            "harmless": last_analysis.get('harmless', 0),
            "failure": last_analysis.get('failure', 0),
            "timeout": last_analysis.get('timeout', 0)
        }
        
        # Calculate detection ratio
        total_scans = sum(last_analysis.values()) if last_analysis else 0
        detections = last_analysis.get('malicious', 0) + last_analysis.get('suspicious', 0)
        file_info['detection_ratio'] = f"{detections}/{total_scans}" if total_scans > 0 else "0/0"
        
        # Analysis date
        last_analysis_date = attributes.get('last_analysis_date')
        if last_analysis_date:
            file_info['last_analysis_date'] = datetime.fromtimestamp(last_analysis_date).isoformat()
        
        # Signature information
        signature_info = attributes.get('signature_info', {})
        if signature_info:
            file_info['signature'] = {
                "verified": signature_info.get('verified', ''),
                "product": signature_info.get('product', ''),
                "description": signature_info.get('description', ''),
                "copyright": signature_info.get('copyright', ''),
                "signers": signature_info.get('signers', '')
            }
        
        # Popular threat names
        popular_threat_category = attributes.get('popular_threat_classification', {})
        if popular_threat_category:
            file_info['threat_classification'] = {
                "suggested_threat_label": popular_threat_category.get('suggested_threat_label', ''),
                "popular_threat_category": popular_threat_category.get('popular_threat_category', [])
            }
        
        # Tags
        tags = attributes.get('tags', [])
        if tags:
            file_info['tags'] = tags
        
        # Extract vendor and product information from signature or names
        vendor = None
        product = None
        
        if signature_info:
            # Try to extract from signature
            vendor = signature_info.get('signers', '') or signature_info.get('copyright', '')
            product = signature_info.get('product', '') or signature_info.get('description', '')
        
        if not product and names:
            # Try to extract from primary filename
            product = names[0]
        
        file_info['vendor'] = vendor
        file_info['product'] = product
        file_info['source'] = "VirusTotal"
        file_info['source_type'] = "independent"
        file_info['source_url'] = f"https://www.virustotal.com/gui/file/{file_info['sha1']}"
        
        return file_info


class WebSourceFetcher:
    """Fetch additional context from web sources"""
    
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }
    
    def fetch_vendor_security_page(self, url: str) -> Optional[str]:
        """Attempt to fetch vendor security page content"""
        
        # Common security page paths
        security_paths = [
            "/security",
            "/trust",
            "/security-practices",
            "/responsible-disclosure",
            "/bug-bounty"
        ]
        
        try:
            # Try the main URL first
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.text[:50000]  # Limit content size
                
        except Exception as e:
            logger.debug(f"Could not fetch {url}: {e}")
        
        return None


class EPSSAPI:
    """Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org"""
    
    def __init__(self):
        self.base_url = "https://api.first.org/data/v1/epss"
        
    def get_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        Fetch EPSS scores for a list of CVE IDs
        
        Args:
            cve_ids: List of CVE IDs (e.g., ['CVE-2022-27225', 'CVE-2022-27223'])
            
        Returns:
            Dictionary mapping CVE ID to EPSS data: {
                'CVE-2022-27225': {
                    'epss': 0.32,
                    'percentile': 0.95,
                    'date': '2024-11-15'
                }
            }
        """
        if not cve_ids:
            return {}
        
        try:
            # Batch request - join CVE IDs with commas
            cve_list = ','.join(cve_ids[:100])  # Limit to 100 CVEs per request
            
            params = {
                'cve': cve_list
            }
            
            logger.info(f"Fetching EPSS scores for {len(cve_ids[:100])} CVEs")
            print(f"\n=== EPSS API REQUEST ===")
            print(f"URL: {self.base_url}")
            print(f"CVE list: {cve_list}")
            
            response = requests.get(
                self.base_url,
                params=params,
                timeout=15
            )
            
            print(f"Response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Response data keys: {data.keys() if data else 'None'}")
                
                # Parse response
                epss_data = {}
                if 'data' in data:
                    print(f"Number of items in data: {len(data['data'])}")
                    for item in data['data']:
                        cve_id = item.get('cve')
                        if cve_id:
                            epss_data[cve_id] = {
                                'epss': float(item.get('epss', 0)),
                                'percentile': float(item.get('percentile', 0)),
                                'date': item.get('date', ''),
                                'source': 'FIRST.org EPSS'
                            }
                            print(f"  {cve_id}: EPSS={item.get('epss')}")
                
                logger.info(f"Retrieved EPSS scores for {len(epss_data)} CVEs")
                print(f"Total EPSS scores retrieved: {len(epss_data)}")
                print(f"========================\n")
                return epss_data
            else:
                logger.warning(f"EPSS API returned status {response.status_code}")
                return {}
                
        except Exception as e:
            logger.error(f"Error fetching EPSS scores: {e}")
            return {}
