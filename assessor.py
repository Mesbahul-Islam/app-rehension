"""
Core assessment engine that orchestrates data gathering and analysis
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from data_sources import ProductHuntAPI, NVDAPI, CISAKEVAPI
from llm_analyzer import GeminiAnalyzer
from database import AssessmentCache
from evidence import EvidenceRegistry
from trust_scorer import TrustScorer

logger = logging.getLogger(__name__)


class SecurityAssessor:
    """Main assessment engine"""
    
    def __init__(self, config):
        self.config = config
        
        # Initialize components
        self.product_hunt = ProductHuntAPI(config.PRODUCTHUNT_API_KEY) if config.PRODUCTHUNT_API_KEY else None
        self.nvd = NVDAPI(api_key=config.NVD_API_KEY)
        self.cisa_kev = CISAKEVAPI()
        self.analyzer = GeminiAnalyzer(config.GEMINI_API_KEY, config.GEMINI_MODEL)
        self.cache = AssessmentCache(config.DATABASE_PATH)
        self.trust_scorer = TrustScorer()
        
        logger.info("SecurityAssessor initialized with NVD API and TrustScorer")
    
    def assess_product(self, input_text: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Main assessment workflow
        
        Args:
            input_text: Product name, vendor, or URL
            use_cache: Whether to use cached results if available
            
        Returns:
            Comprehensive security assessment
        """
        logger.info(f"Starting assessment for: {input_text}")
        
        # Check cache first
        if use_cache:
            cached = self.cache.get_assessment(input_text, max_age_hours=self.config.CACHE_EXPIRY_HOURS)
            if cached:
                logger.info(f"Returning cached assessment for: {input_text}")
                return cached
        
        # Initialize evidence registry for this assessment
        evidence_registry = EvidenceRegistry()
        
        # Step 1: Gather initial data
        logger.info("Step 1: Gathering product information")
        product_data = self._gather_product_data(input_text)
        
        # Step 2: Resolve entity
        logger.info("Step 2: Resolving entity identity")
        entity_info = self.analyzer.resolve_entity(input_text, product_data, evidence_registry)
        
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')
        
        logger.info(f"Resolved - Product: {product_name}, Vendor: {vendor}")
        
        # Step 3: Classify software
        logger.info("Step 3: Classifying software")
        classification = self.analyzer.classify_software(entity_info, product_data)
        
        # Step 4: Gather security data
        logger.info("Step 4: Gathering security data (CVE, KEV)")
        security_data = self._gather_security_data(vendor, product_name)
        
        # Step 5: Analyze vulnerabilities
        logger.info("Step 5: Analyzing vulnerabilities")
        vuln_analysis = self.analyzer.analyze_vulnerabilities(
            security_data['cves'],
            security_data['kevs'],
            evidence_registry
        )
        
        # Step 6: Gather additional security analysis
        logger.info("Step 6: Analyzing security practices, incidents, compliance, and controls")
        
        security_practices = self.analyzer.analyze_security_practices(
            entity_info, evidence_registry
        )
        
        incidents_analysis = self.analyzer.analyze_incidents(
            entity_info, evidence_registry
        )
        
        data_compliance = self.analyzer.analyze_data_compliance(
            entity_info, evidence_registry
        )
        
        deployment_controls = self.analyzer.analyze_deployment_controls(
            entity_info, classification, evidence_registry
        )
        
        # Step 7: Calculate rule-based trust score
        logger.info("Step 7: Calculating transparent rule-based trust score")
        
        scoring_data = {
            'cves': security_data['cves'],
            'kevs': security_data['kevs'],
            'product_data': product_data,
            'security_practices': security_practices,
            'incidents': incidents_analysis,
            'data_compliance': data_compliance
        }
        
        trust_score = self.trust_scorer.calculate_trust_score(scoring_data)
        
        # Step 8: Suggest alternatives
        logger.info("Step 8: Suggesting alternatives")
        alternatives, alt_evidence_refs = self.analyzer.suggest_alternatives(
            entity_info, classification, trust_score, evidence_registry
        )
        
        # Step 9: Compile final assessment
        logger.info("Step 9: Compiling final assessment with evidence citations")
        assessment = self._compile_assessment(
            entity_info=entity_info,
            classification=classification,
            product_data=product_data,
            security_data=security_data,
            vuln_analysis=vuln_analysis,
            security_practices=security_practices,
            incidents=incidents_analysis,
            data_compliance=data_compliance,
            deployment_controls=deployment_controls,
            trust_score=trust_score,
            alternatives=alternatives,
            evidence_registry=evidence_registry
        )
        
        # Cache the result
        logger.info("Saving assessment to cache")
        self.cache.save_assessment(
            product_name=product_name,
            assessment_data=assessment,
            vendor=vendor,
            url=entity_info.get('url')
        )
        
        logger.info(f"Assessment complete for: {input_text}")
        return assessment
    
    def _gather_product_data(self, input_text: str) -> Optional[Dict[str, Any]]:
        """Gather product information from ProductHunt"""
        
        if not self.product_hunt:
            logger.warning("ProductHunt API not configured")
            return None
        
        try:
            # Check cache first
            cache_key = f"ph_{input_text}"
            cached_data = self.cache.get_raw_data(cache_key)
            if cached_data:
                return cached_data
            
            # Fetch from API
            data = self.product_hunt.search_product(input_text)
            
            # Cache it
            if data:
                self.cache.save_raw_data(cache_key, "producthunt", data, expiry_hours=24)
            
            return data
            
        except Exception as e:
            logger.error(f"Error gathering product data: {e}")
            return None
    
    def _gather_security_data(self, vendor: str, product: Optional[str] = None) -> Dict[str, Any]:
        """Gather CVE and KEV data from NVD and CISA"""
        
        cves = []
        kevs = []
        
        try:
            # Gather CVE data from NVD
            # Priority: 1) Search by product if available, 2) Fall back to vendor
            if product:
                logger.info(f"Fetching CVEs for product: {product}")
                cache_key = f"nvd_cve_{product}"
            else:
                logger.info(f"Fetching CVEs for vendor: {vendor}")
                cache_key = f"nvd_cve_vendor_{vendor}"
            
            cached_cves = self.cache.get_raw_data(cache_key)
            
            if cached_cves:
                cves = cached_cves
                logger.info(f"Using cached CVEs: {len(cves)} found")
            else:
                cves = self.nvd.search_cves(vendor, product, limit=50)
                if cves:
                    self.cache.save_raw_data(cache_key, "cve", cves, expiry_hours=24)
            
            logger.info(f"Total CVEs from NVD: {len(cves)}")
            
        except Exception as e:
            logger.error(f"Error gathering CVE data from NVD: {e}")
        
        try:
            # Gather KEV data from CISA
            logger.info(f"Fetching KEVs for vendor: {vendor}, product: {product or 'all'}")
            cache_key = f"kev_{vendor}_{product or 'all'}"
            cached_kevs = self.cache.get_raw_data(cache_key)
            
            if cached_kevs:
                kevs = cached_kevs
                logger.info(f"Using cached KEVs: {len(kevs)} found")
            else:
                kevs = self.cisa_kev.search_kev(vendor, product)
                if kevs:
                    self.cache.save_raw_data(cache_key, "kev", kevs, expiry_hours=24)
            
            logger.info(f"Total KEVs from CISA: {len(kevs)}")
            
        except Exception as e:
            logger.error(f"Error gathering KEV data: {e}")
        
        return {
            'cves': cves,
            'kevs': kevs
        }
    
    def _compile_assessment(self, entity_info: Dict, classification: Dict,
                          product_data: Optional[Dict], security_data: Dict,
                          vuln_analysis: Dict, security_practices: Dict,
                          incidents: Dict, data_compliance: Dict,
                          deployment_controls: Dict, trust_score: Dict,
                          alternatives: list, evidence_registry=None) -> Dict[str, Any]:
        """Compile all information into final assessment"""
        
        # Get evidence summary and citations
        evidence_summary = {}
        citations = []
        evidence_hash = None
        
        if evidence_registry:
            evidence_summary = evidence_registry.get_summary()
            citations = evidence_registry.get_citations_list()
            evidence_hash = evidence_registry.get_evidence_hash()
        
        assessment = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'version': '1.0',
                'input_query': entity_info.get('product_name'),
                'evidence_hash': evidence_hash
            },
            'entity': {
                'product_name': entity_info.get('product_name'),
                'vendor': entity_info.get('vendor'),
                'url': entity_info.get('url'),
                'aliases': entity_info.get('aliases', []),
                'confidence': entity_info.get('confidence'),
                'evidence_refs': entity_info.get('evidence_refs', [])
            },
            'classification': {
                'category': classification.get('primary_category'),
                'sub_category': classification.get('sub_category'),
                'additional_categories': classification.get('additional_categories', []),
                'use_cases': classification.get('use_cases', []),
                'deployment_model': classification.get('deployment_model')
            },
            'description': {
                'summary': product_data.get('description') if product_data else 'No description available',
                'tagline': product_data.get('tagline') if product_data else None,
                'topics': product_data.get('topics', []) if product_data else []
            },
            'security_posture': {
                'vulnerability_summary': {
                    'total_cves': len(security_data['cves']),
                    'total_kevs': len(security_data['kevs']),
                    'trend': vuln_analysis.get('trend'),
                    'exploitation_risk': vuln_analysis.get('exploitation_risk'),
                    'severity_distribution': vuln_analysis.get('severity_distribution', {}),
                    'critical_findings': vuln_analysis.get('critical_findings', []),
                    'key_concerns': vuln_analysis.get('key_concerns', []),
                    'positive_signals': vuln_analysis.get('positive_signals', []),
                    'evidence_quality': vuln_analysis.get('evidence_quality', 'unknown'),
                    'evidence_refs': vuln_analysis.get('evidence_refs', [])
                },
                'recent_cves': security_data['cves'][:5],  # Top 5 recent/critical
                'kev_list': security_data['kevs'][:5]  # Top 5 KEVs
            },
            'trust_score': {
                'total_score': trust_score.get('total_score'),
                'risk_level': trust_score.get('risk_level'),
                'confidence': trust_score.get('confidence'),
                'components': trust_score.get('components', {}),
                'calculation_method': trust_score.get('calculation_method'),
                'weights': trust_score.get('weights', {}),
                'timestamp': trust_score.get('timestamp')
            },
            'security_practices': {
                'rating': security_practices.get('rating'),
                'bug_bounty': security_practices.get('bug_bounty'),
                'disclosure_policy': security_practices.get('disclosure_policy'),
                'security_team_visible': security_practices.get('security_team_visible'),
                'patch_cadence': security_practices.get('patch_cadence'),
                'summary': security_practices.get('summary'),
                'evidence_refs': security_practices.get('evidence_refs', [])
            },
            'incidents': {
                'count': incidents.get('count', 0),
                'severity': incidents.get('severity'),
                'incidents': incidents.get('incidents', []),
                'rating': incidents.get('rating'),
                'summary': incidents.get('summary'),
                'evidence_refs': incidents.get('evidence_refs', [])
            },
            'data_compliance': {
                'status': data_compliance.get('status'),
                'certifications': data_compliance.get('certifications', []),
                'gdpr_compliant': data_compliance.get('gdpr_compliant'),
                'data_residency': data_compliance.get('data_residency'),
                'privacy_rating': data_compliance.get('privacy_rating'),
                'summary': data_compliance.get('summary'),
                'evidence_refs': data_compliance.get('evidence_refs', [])
            },
            'deployment_controls': {
                'sso_support': deployment_controls.get('sso_support'),
                'mfa_support': deployment_controls.get('mfa_support'),
                'rbac_available': deployment_controls.get('rbac_available'),
                'audit_logging': deployment_controls.get('audit_logging'),
                'control_rating': deployment_controls.get('control_rating'),
                'key_features': deployment_controls.get('key_features', []),
                'limitations': deployment_controls.get('limitations', []),
                'summary': deployment_controls.get('summary'),
                'evidence_refs': deployment_controls.get('evidence_refs', [])
            },
            'alternatives': alternatives,
            'recommendations': self._generate_recommendations(trust_score, vuln_analysis, incidents),
            'sources': self._compile_sources(product_data, security_data),
            'evidence_summary': evidence_summary,
            'citations': citations
        }
        
        return assessment
    
    def _generate_recommendations(self, trust_score: Dict, vuln_analysis: Dict, incidents: Dict) -> list:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        score = trust_score.get('total_score', 50)
        risk_level = trust_score.get('risk_level', 'medium')
        
        if score < 40 or risk_level == 'critical':
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Do not approve without thorough security review',
                'reason': 'Low trust score indicates significant security concerns'
            })
        elif score < 60 or risk_level == 'high':
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Require vendor security assessment and remediation plan',
                'reason': 'Multiple security concerns identified'
            })
        else:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Proceed with standard security review',
                'reason': 'Acceptable security posture with manageable risks'
            })
        
        # KEV-specific recommendation
        if vuln_analysis.get('exploitation_risk') in ['high', 'critical']:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Verify all KEV vulnerabilities are patched',
                'reason': 'Known exploited vulnerabilities present'
            })
        
        # Incident-specific recommendations
        incident_severity = incidents.get('severity', 'none')
        if incident_severity in ['high', 'critical']:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Review incident response history and vendor transparency',
                'reason': f'Vendor has history of {incident_severity} severity security incidents'
            })
        
        return recommendations
    
    def _compile_sources(self, product_data: Optional[Dict], security_data: Dict) -> list:
        """Compile list of data sources with timestamps"""
        
        sources = []
        
        if product_data:
            sources.append({
                'name': 'ProductHunt',
                'type': 'Product Information',
                'timestamp': datetime.now().isoformat()
            })
        
        if security_data['cves']:
            sources.append({
                'name': 'NVD (National Vulnerability Database)',
                'type': 'CVE Data',
                'url': 'https://nvd.nist.gov',
                'count': len(security_data['cves']),
                'timestamp': datetime.now().isoformat()
            })
        
        if security_data['kevs']:
            sources.append({
                'name': 'CISA KEV Catalog',
                'type': 'Known Exploited Vulnerabilities',
                'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
                'count': len(security_data['kevs']),
                'timestamp': datetime.now().isoformat()
            })
        
        return sources
    
    def get_assessment_history(self, limit: int = 100) -> list:
        """Get list of all cached assessments"""
        return self.cache.get_all_assessments(limit)
