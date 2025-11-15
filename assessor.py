"""
Core assessment engine that orchestrates data gathering and analysis
"""
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from data_sources import ProductHuntAPI, NVDAPI, CISAKEVAPI, VirusTotalAPI, EPSSAPI
from llm_analyzer import GeminiAnalyzer
from multi_agent_analyzer import MultiAgentAnalyzer
from database import AssessmentCache
from evidence import EvidenceRegistry
from trust_scorer import TrustScorer
from virustotal_trust_scorer import VirusTotalTrustScorer

class SecurityAssessor:
    """Main assessment engine"""
    
    def __init__(self, config):
        self.config = config
        
        # Initialize components
        self.product_hunt = ProductHuntAPI(config.PRODUCTHUNT_API_KEY) if config.PRODUCTHUNT_API_KEY else None
        self.nvd = NVDAPI(api_key=config.NVD_API_KEY)
        self.cisa_kev = CISAKEVAPI()
        self.epss = EPSSAPI()
        self.virustotal = VirusTotalAPI(config.VIRUSTOTAL_API_KEY) if config.VIRUSTOTAL_API_KEY else None
        
        # Initialize analyzer based on configuration
        self.use_multi_agent = config.USE_MULTI_AGENT
        
        if self.use_multi_agent:
            self.multi_agent = MultiAgentAnalyzer(config.GEMINI_API_KEY, config.GEMINI_MODEL)
            # Always initialize single-agent for utility functions
            self.analyzer = GeminiAnalyzer(config.GEMINI_API_KEY, config.GEMINI_MODEL)
        else:

            self.analyzer = GeminiAnalyzer(config.GEMINI_API_KEY, config.GEMINI_MODEL)
            self.multi_agent = None
        
        self.cache = AssessmentCache(config.DATABASE_PATH)
        self.trust_scorer = TrustScorer()
        self.virustotal_trust_scorer = VirusTotalTrustScorer()

    def assess_product(self, input_text: str, use_cache: bool = True, progress_callback: Optional[Callable] = None, 
                      virustotal_data: Optional[Dict] = None, search_term: Optional[str] = None) -> Dict[str, Any]:
        """
        Main assessment workflow
        
        Args:
            input_text: Product name, vendor, or URL
            use_cache: Whether to use cached results if available
            progress_callback: Optional callback for progress updates
            virustotal_data: Optional VirusTotal data from SHA1 hash lookup
            search_term: Original user-provided search query (for cache key stability)
            
        Returns:
            Comprehensive security assessment
        """

        normalized_search_term = search_term or input_text
        
        logger.info(f"[CACHE] assess_product called: input_text='{input_text}', search_term='{search_term}', use_cache={use_cache}")

        if use_cache and normalized_search_term:
            logger.info("[CACHE] Checking cache before API calls...")
            cached_query_result = self.cache.get_assessment_by_query(
                normalized_search_term,
                max_age_hours=self.config.CACHE_EXPIRY_HOURS
            )
            if cached_query_result:
                logger.info(f"[CACHE] ✓ HIT - Returning cached result for '{normalized_search_term}'")
                if progress_callback:
                    progress_callback({
                        "stage": "cache",
                        "status": "completed",
                        "details": "Returning cached assessment for this search"
                    })
                return cached_query_result
            else:
                logger.info(f"[CACHE] ✗ MISS - Will perform full assessment for '{normalized_search_term}'")

        if virustotal_data:

            logger.info(f"  File: {virustotal_data.get('primary_name', 'Unknown')}")
            logger.info(f"  Detection: {virustotal_data.get('detection_ratio', 'N/A')}")
        
        # Notify initial progress
        if progress_callback:
            progress_callback({
                "stage": "initialization",
                "status": "in_progress",
                "details": "Starting assessment workflow..."
            })
        
        # Initialize evidence registry for this assessment
        evidence_registry = EvidenceRegistry()
        
        # Step 1: Gather initial data

        if progress_callback:
            progress_callback({
                "stage": "data_gathering",
                "status": "in_progress",
                "details": "Gathering product information..."
            })
        
        # If VirusTotal data is provided, use it instead of ProductHunt
        if virustotal_data:

            product_data = self._format_virustotal_as_product_data(virustotal_data)
        else:
            product_data = self._gather_product_data(input_text)
        
        # Step 2: Resolve entity (need single-agent for this)

        if progress_callback:
            progress_callback({
                "stage": "entity_resolution",
                "status": "in_progress",
                "details": "Resolving product and vendor identity..."
            })
        
        # If VirusTotal data is available, use it directly for entity info
        if virustotal_data:

            entity_info = {
                'product_name': virustotal_data.get('product') or virustotal_data.get('primary_name'),
                'vendor': virustotal_data.get('vendor'),
                'url': virustotal_data.get('source_url'),
                'aliases': virustotal_data.get('names', [])[:5],  # Limit aliases
                'confidence': 'high',  # VirusTotal data is highly reliable
                'evidence_refs': ['virustotal_file_analysis']
            }
        else:
            # For entity resolution, use single-agent (quick lookup)
            entity_info = self.analyzer.resolve_entity(input_text, product_data, evidence_registry)
        
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')

        # Check cache again with resolved product/vendor
        if use_cache and (product_name or vendor):
            cached = self.cache.get_assessment(
                product_name=product_name, 
                vendor=vendor if not product_name else None,
                max_age_hours=self.config.CACHE_EXPIRY_HOURS
            )
            if cached:

                if progress_callback:
                    progress_callback({
                        "stage": "cache",
                        "status": "completed",
                        "details": "Using cached results"
                    })
                return cached
        
        # Step 3: Classify software

        classification = self.analyzer.classify_software(entity_info, product_data)
        
        # Step 4: Gather security data
        if progress_callback:
            progress_callback({
                "stage": "security_data",
                "status": "in_progress",
                "details": f"Fetching CVE and KEV data for {vendor}..."
            })
        
        security_data = self._gather_security_data(vendor, product_name)
        
        # Decision point: Use multi-agent or single-agent for analysis
        if self.use_multi_agent and self.multi_agent:
            return self._assess_with_multi_agent(
                input_text=input_text,
                entity_info=entity_info,
                classification=classification,
                product_data=product_data,
                security_data=security_data,
                evidence_registry=evidence_registry,
                progress_callback=progress_callback,
                virustotal_data=virustotal_data,
                search_term=normalized_search_term
            )
        else:
            return self._assess_with_single_agent(
                input_text=input_text,
                entity_info=entity_info,
                classification=classification,
                product_data=product_data,
                security_data=security_data,
                evidence_registry=evidence_registry,
                virustotal_data=virustotal_data,
                search_term=normalized_search_term
            )
    
    def _assess_with_multi_agent(
        self,
        input_text: str,
        entity_info: Dict,
        classification: Dict,
        product_data: Dict,
        security_data: Dict,
        evidence_registry: EvidenceRegistry,
        progress_callback: Optional[Callable] = None,
        virustotal_data: Optional[Dict] = None,
        search_term: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Multi-agent assessment workflow with research → verification → synthesis
        """

        # Determine analysis mode based on data source
        is_virustotal_analysis = virustotal_data is not None
        
        # For VirusTotal-only analysis (SHA1 hash lookup), skip LLM analysis
        if is_virustotal_analysis:
            if progress_callback:
                progress_callback({
                    "stage": "analysis",
                    "status": "in_progress",
                    "details": "Processing VirusTotal data (no LLM analysis required)"
                })
            
            # Use empty/default values for LLM-based analysis
            security_practices = {
                'rating': 'unknown',
                'bug_bounty': False,
                'disclosure_policy': False,
                'security_team_visible': False,
                'patch_cadence': 'unknown',
                'summary': 'Security practices assessment not applicable for file hash analysis',
                'evidence_refs': []
            }
            
            incidents_analysis = {
                'count': 0,
                'severity': 'none',
                'incidents': [],
                'rating': 'unknown',
                'summary': 'Security incidents assessment not applicable for file hash analysis',
                'evidence_refs': []
            }
            
            data_compliance = {
                'not_applicable': True,
                'reason': 'Data compliance assessment not applicable for file hash analysis',
                'data_source': 'not_applicable'
            }
            
            deployment_controls = {
                'not_applicable': True,
                'reason': 'Deployment controls assessment not applicable for file hash analysis',
                'data_source': 'not_applicable'
            }
            
            # Simple vulnerability analysis from VirusTotal detection stats
            vuln_analysis = {
                'summary': f"VirusTotal analysis: {virustotal_data.get('detection_ratio', '0/0')} detections",
                'trend': 'stable',
                'exploitation_risk': 'high' if virustotal_data.get('detection_stats', {}).get('malicious', 0) > 0 else 'low',
                'severity_distribution': {},
                'critical_findings': [],
                'key_concerns': [],
                'positive_signals': [],
                'evidence_quality': 'high',
                'evidence_refs': []
            }
            
            # Calculate VirusTotal-based trust score
            trust_score = self.virustotal_trust_scorer.calculate_trust_score(virustotal_data)
            
            # No alternatives for file hash analysis
            alternatives = []
            
        else:
            # Normal product assessment with LLM analysis

            # Use single-agent for structured components (needed for trust scoring)

            security_practices = self.analyzer.analyze_security_practices(
                entity_info, evidence_registry
            )
            
            incidents_analysis = self.analyzer.analyze_incidents(
                entity_info, evidence_registry
            )
            
            # Skip data compliance and deployment controls for vendor-only assessments
            is_vendor_only = not entity_info.get('product_name')
            
            if is_vendor_only:

                data_compliance = {
                    'not_applicable': True,
                    'reason': 'Data compliance assessment requires a specific product',
                    'data_source': 'not_applicable'
                }
                deployment_controls = {
                    'not_applicable': True,
                    'reason': 'Deployment controls assessment requires a specific product',
                    'data_source': 'not_applicable'
                }
            else:
                data_compliance = self.analyzer.analyze_data_compliance(
                    entity_info, evidence_registry
                )
                
                deployment_controls = self.analyzer.analyze_deployment_controls(
                    entity_info, classification, evidence_registry
                )
            
            # Run multi-agent verification analysis

            multi_agent_result = self.multi_agent.analyze_with_verification(
                entity_info=entity_info,
                cve_data=security_data['cves'],
                kev_data=security_data['kevs'],
                security_practices=security_practices,
                incidents=incidents_analysis,
                data_compliance=data_compliance,
                deployment_controls=deployment_controls,
                progress_callback=progress_callback,
                virustotal_data=virustotal_data,
                is_virustotal_analysis=is_virustotal_analysis
            )
            
            # Extract verified vulnerability analysis from multi-agent result
            vuln_analysis = multi_agent_result.get('vulnerability_analysis', {})
            
            # Fallback to single-agent if multi-agent failed
            if not vuln_analysis or 'error' in multi_agent_result:
                vuln_analysis = self.analyzer.analyze_vulnerabilities(
                    security_data['cves'],
                    security_data['kevs'],
                    evidence_registry
                )
            
            # Calculate rule-based trust score (use VirusTotal scorer if applicable)
            if virustotal_data:

                trust_score = self.virustotal_trust_scorer.calculate_trust_score(virustotal_data)
            else:

                # Fetch EPSS scores for all CVEs
                cve_ids = [cve.get('cve_id') for cve in security_data['cves'] if cve.get('cve_id')]
                print(f"\n=== EPSS FETCHING IN ASSESSOR ===")
                print(f"CVE IDs to fetch EPSS for: {cve_ids}")
                epss_data = self.epss.get_epss_scores(cve_ids) if cve_ids else {}
                print(f"EPSS data fetched: {epss_data}")
                print(f"================================\n")
                
                scoring_data = {
                    'cves': security_data['cves'],
                    'kevs': security_data['kevs'],
                    'epss_data': epss_data,
                    'product_data': product_data,
                    'security_practices': security_practices,
                    'incidents': incidents_analysis,
                    'data_compliance': data_compliance
                }
                trust_score = self.trust_scorer.calculate_trust_score(scoring_data)
            
            # Suggest alternatives (only for normal product assessments)
            alternatives, alt_evidence_refs = self.analyzer.suggest_alternatives(
                entity_info, classification, trust_score, evidence_registry
            )
            
            # Score each alternative with the same CVSS+EPSS+KEV system
            scored_alternatives = []
            for alt in alternatives:
                alt_product = alt.get('product_name')
                alt_vendor = alt.get('vendor')
                
                if alt_product:
                    alt_assessment = self.assess_alternative(alt_product, alt_vendor)
                    
                    # Merge LLM suggestions with actual scores
                    alt['trust_score'] = alt_assessment.get('trust_score')
                    alt['risk_level'] = alt_assessment.get('risk_level')
                    alt['cve_count'] = alt_assessment.get('cve_count', 0)
                    alt['kev_count'] = alt_assessment.get('kev_count', 0)
                    alt['scoring_breakdown'] = alt_assessment.get('scoring_breakdown', {})
                    alt['assessed'] = alt_assessment.get('trust_score') is not None
                    
                    scored_alternatives.append(alt)
            
            # Sort alternatives by trust score (highest first)
            scored_alternatives.sort(key=lambda x: x.get('trust_score') or 0, reverse=True)
            alternatives = scored_alternatives
        
        # Compile final assessment

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
            evidence_registry=evidence_registry,
            virustotal_data=virustotal_data
        )
        
        # Add analysis mode metadata
        if is_virustotal_analysis:
            assessment['_analysis_mode'] = 'virustotal'
        else:
            assessment['_analysis_mode'] = 'multi-agent'
            assessment['_multi_agent_metadata'] = multi_agent_result.get('_multi_agent_metadata', {})
            
            # Merge multi-agent citations with evidence registry citations
            if 'citations' in multi_agent_result:
                # Add multi-agent citations to the existing citations list
                existing_citations = assessment.get('citations', [])
                multi_agent_citations = multi_agent_result['citations']
                
                # Combine and deduplicate by URL
                all_citations = existing_citations.copy()
                existing_urls = {c.get('url') for c in existing_citations if c.get('url')}
                
                for citation in multi_agent_citations:
                    if citation.get('url') not in existing_urls:
                        all_citations.append(citation)
                
                assessment['citations'] = all_citations
        
        # Cache the result
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')
        cache_query = search_term or input_text

        logger.info(f"[CACHE] Saving assessment for query: '{cache_query}'")
        self.cache.save_assessment(
            product_name=product_name,
            assessment_data=assessment,
            vendor=vendor,
            url=entity_info.get('url'),
            search_term=cache_query
        )

        return assessment
    
    def _assess_with_single_agent(
        self,
        input_text: str,
        entity_info: Dict,
        classification: Dict,
        product_data: Dict,
        security_data: Dict,
        evidence_registry: EvidenceRegistry,
        virustotal_data: Optional[Dict] = None,
        search_term: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Traditional single-agent assessment workflow
        """

        # Step 5: Analyze vulnerabilities

        vuln_analysis = self.analyzer.analyze_vulnerabilities(
            security_data['cves'],
            security_data['kevs'],
            evidence_registry
        )
        
        # Step 6: Gather additional security analysis

        security_practices = self.analyzer.analyze_security_practices(
            entity_info, evidence_registry
        )
        
        incidents_analysis = self.analyzer.analyze_incidents(
            entity_info, evidence_registry
        )
        
        # Skip data compliance and deployment controls for vendor-only assessments
        is_vendor_only = not entity_info.get('product_name')
        
        if is_vendor_only:

            data_compliance = {
                'not_applicable': True,
                'reason': 'Data compliance assessment requires a specific product',
                'data_source': 'not_applicable'
            }
            deployment_controls = {
                'not_applicable': True,
                'reason': 'Deployment controls assessment requires a specific product',
                'data_source': 'not_applicable'
            }
        else:
            data_compliance = self.analyzer.analyze_data_compliance(
                entity_info, evidence_registry
            )
            
            deployment_controls = self.analyzer.analyze_deployment_controls(
                entity_info, classification, evidence_registry
            )
        
        # Step 7: Calculate rule-based trust score (use VirusTotal scorer if applicable)

        if virustotal_data:

            trust_score = self.virustotal_trust_scorer.calculate_trust_score(virustotal_data)
        else:

            # Fetch EPSS scores for all CVEs
            cve_ids = [cve.get('cve_id') for cve in security_data['cves'] if cve.get('cve_id')]
            print(f"\n=== EPSS FETCHING IN ASSESSOR (single-agent) ===")
            print(f"CVE IDs to fetch EPSS for: {cve_ids}")
            epss_data = self.epss.get_epss_scores(cve_ids) if cve_ids else {}
            print(f"EPSS data fetched: {epss_data}")
            print(f"================================================\n")
            
            scoring_data = {
                'cves': security_data['cves'],
                'kevs': security_data['kevs'],
                'epss_data': epss_data,
                'product_data': product_data,
                'security_practices': security_practices,
                'incidents': incidents_analysis,
                'data_compliance': data_compliance
            }
            trust_score = self.trust_scorer.calculate_trust_score(scoring_data)
        
        # Step 8: Suggest alternatives

        alternatives, alt_evidence_refs = self.analyzer.suggest_alternatives(
            entity_info, classification, trust_score, evidence_registry
        )
        
        # Score each alternative with the same CVSS+EPSS+KEV system
        scored_alternatives = []
        for alt in alternatives:
            alt_product = alt.get('product_name')
            alt_vendor = alt.get('vendor')
            
            if alt_product:
                alt_assessment = self.assess_alternative(alt_product, alt_vendor)
                
                # Merge LLM suggestions with actual scores
                alt['trust_score'] = alt_assessment.get('trust_score')
                alt['risk_level'] = alt_assessment.get('risk_level')
                alt['cve_count'] = alt_assessment.get('cve_count', 0)
                alt['kev_count'] = alt_assessment.get('kev_count', 0)
                alt['scoring_breakdown'] = alt_assessment.get('scoring_breakdown', {})
                alt['assessed'] = alt_assessment.get('trust_score') is not None
                
                scored_alternatives.append(alt)
        
        # Sort alternatives by trust score (highest first)
        scored_alternatives.sort(key=lambda x: x.get('trust_score') or 0, reverse=True)
        alt_scores = ["{} ({})".format(a.get('product_name'), a.get('trust_score')) for a in scored_alternatives]
        
        # Step 9: Compile final assessment

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
            alternatives=scored_alternatives,
            evidence_registry=evidence_registry,
            virustotal_data=virustotal_data
        )
        
        # Add single-agent metadata
        assessment['_analysis_mode'] = 'single-agent'
        
        # Cache the result
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')
        cache_query = search_term or input_text

        logger.info(f"[CACHE] Saving assessment for query: '{cache_query}'")
        self.cache.save_assessment(
            product_name=product_name,
            assessment_data=assessment,
            vendor=vendor,
            url=entity_info.get('url'),
            search_term=cache_query
        )

        return assessment
    
    def _gather_product_data(self, input_text: str) -> Optional[Dict[str, Any]]:
        """Gather product information from ProductHunt"""
        
        if not self.product_hunt:
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
            return None
    
    def _format_virustotal_as_product_data(self, virustotal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format VirusTotal data to match ProductHunt data structure"""
        
        # Extract meaningful description from VirusTotal data
        description_parts = []
        
        if virustotal_data.get('type'):
            description_parts.append(f"File type: {virustotal_data['type']}")
        
        signature = virustotal_data.get('signature', {})
        if signature and signature.get('description'):
            description_parts.append(signature['description'])
        elif signature and signature.get('product'):
            description_parts.append(signature['product'])
        
        # Add detection information
        detection_stats = virustotal_data.get('detection_stats', {})
        malicious = detection_stats.get('malicious', 0)
        suspicious = detection_stats.get('suspicious', 0)
        
        if malicious > 0:
            description_parts.append(f"⚠️ {malicious} antivirus engines detected this as malicious")
        elif suspicious > 0:
            description_parts.append(f"⚠️ {suspicious} antivirus engines flagged this as suspicious")
        else:
            description_parts.append("✓ No malicious detections reported")
        
        description = ". ".join(description_parts) if description_parts else "File analyzed by VirusTotal"
        
        # Create a ProductHunt-like data structure
        return {
            'name': virustotal_data.get('product') or virustotal_data.get('primary_name'),
            'description': description,
            'tagline': f"Verified by VirusTotal - Detection ratio: {virustotal_data.get('detection_ratio', 'N/A')}",
            'url': virustotal_data.get('source_url'),
            'website': None,
            'votes': 0,
            'comments': 0,
            'created_at': virustotal_data.get('last_analysis_date'),
            'topics': virustotal_data.get('tags', []),
            'makers': [virustotal_data.get('vendor')] if virustotal_data.get('vendor') else [],
            'source': 'VirusTotal',
            'source_type': 'independent',
            '_virustotal_analysis': True  # Flag to indicate this came from VirusTotal
        }
    
    def _gather_security_data(self, vendor: str, product: Optional[str] = None) -> Dict[str, Any]:
        """Gather CVE and KEV data from NVD and CISA"""
        
        cves = []
        kevs = []
        
        try:
            # Gather CVE data from NVD
            # Priority: 1) Search by product if available, 2) Fall back to vendor
            if product:

                cache_key = f"nvd_cve_{product}"
            else:

                cache_key = f"nvd_cve_vendor_{vendor}"
            
            cached_cves = self.cache.get_raw_data(cache_key)
            
            if cached_cves:
                cves = cached_cves
            else:
                cves = self.nvd.search_cves(vendor, product, limit=200)
                if cves:
                    self.cache.save_raw_data(cache_key, "cve", cves, expiry_hours=24)
            
        except Exception as e:
            pass
        
        try:
            # Gather KEV data from CISA
            cache_key = f"kev_{vendor}_{product or 'all'}"
            cached_kevs = self.cache.get_raw_data(cache_key)
            
            if cached_kevs:
                kevs = cached_kevs
            else:
                kevs = self.cisa_kev.search_kev(vendor, product)
                if kevs:
                    self.cache.save_raw_data(cache_key, "kev", kevs, expiry_hours=24)
            
        except Exception as e:
            pass
        
        return {
            'cves': cves,
            'kevs': kevs
        }
    
    def _aggregate_cves_by_year(self, cves: list) -> Dict[str, int]:
        """Aggregate CVEs by year for timeline visualization"""
        timeline = {}
        
        for cve in cves:
            try:
                # published_date is in format 'YYYY-MM-DDTHH:MM:SS.000'
                published_date = cve.get('published_date', '')
                year = published_date[:4]
                if year and year.isdigit():
                    timeline[year] = timeline.get(year, 0) + 1
            except Exception as e:
                continue
        
        sorted_timeline = dict(sorted(timeline.items()))
        return sorted_timeline  # Sort by year
    
    def _compile_assessment(self, entity_info: Dict, classification: Dict,
                          product_data: Optional[Dict], security_data: Dict,
                          vuln_analysis: Dict, security_practices: Dict,
                          incidents: Dict, data_compliance: Dict,
                          deployment_controls: Dict, trust_score: Dict,
                          alternatives: list, evidence_registry=None, virustotal_data: Optional[Dict] = None) -> Dict[str, Any]:
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
                'input_query': entity_info.get('product_name') or entity_info.get('vendor'),
                'assessment_type': 'product' if entity_info.get('product_name') else 'vendor',
                'evidence_hash': evidence_hash,
                'virustotal_analysis': True if virustotal_data else False
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
                'total_cves': len(security_data['cves']),
                'total_kevs': len(security_data['kevs']),
                'kev_count': len(security_data['kevs']),
                'critical_cves': vuln_analysis.get('severity_distribution', {}).get('CRITICAL', 0),
                'high_cves': vuln_analysis.get('severity_distribution', {}).get('HIGH', 0),
                'medium_cves': vuln_analysis.get('severity_distribution', {}).get('MEDIUM', 0),
                'low_cves': vuln_analysis.get('severity_distribution', {}).get('LOW', 0),
                'vulnerability_summary': {
                    'total_cves': len(security_data['cves']),
                    'total_kevs': len(security_data['kevs']),
                    'summary': vuln_analysis.get('summary'),
                    'trend': vuln_analysis.get('trend'),
                    'exploitation_risk': vuln_analysis.get('exploitation_risk'),
                    'severity_distribution': vuln_analysis.get('severity_distribution', {}),
                    'critical_findings': vuln_analysis.get('critical_findings', []),
                    'key_concerns': vuln_analysis.get('key_concerns', []),
                    'positive_signals': vuln_analysis.get('positive_signals', []),
                    'evidence_quality': vuln_analysis.get('evidence_quality', 'unknown'),
                    'evidence_refs': vuln_analysis.get('evidence_refs', []),
                    'cve_timeline': self._aggregate_cves_by_year(security_data['cves'])
                },
                'recent_cves': security_data['cves'][:5],  # Top 5 recent/critical
                'kev_list': security_data['kevs'][:5]  # Top 5 KEVs
            },
            'trust_score': {
                'score': trust_score.get('score'),  # New CVSS+EPSS+KEV scoring
                'total_score': trust_score.get('total_score') or trust_score.get('score'),  # Backwards compatibility
                'risk_level': trust_score.get('risk_level'),
                'confidence': trust_score.get('confidence'),
                'components': trust_score.get('components', {}),
                'scoring_breakdown': trust_score.get('scoring_breakdown', {}),
                'key_factors': trust_score.get('key_factors', []),
                'data_limitations': trust_score.get('data_limitations', []),
                'rationale': trust_score.get('rationale'),
                'calculation_method': trust_score.get('calculation_method'),
                'weights': trust_score.get('weights', {}),
                'timestamp': trust_score.get('timestamp'),
                'insufficient_data': trust_score.get('insufficient_data', False)  # Flag for insufficient data
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
                'not_applicable': data_compliance.get('not_applicable', False),
                'reason': data_compliance.get('reason'),
                'data_source': data_compliance.get('data_source'),
                'status': data_compliance.get('status'),
                'certifications': data_compliance.get('certifications', []),
                'gdpr_compliant': data_compliance.get('gdpr_compliant'),
                'data_residency': data_compliance.get('data_residency'),
                'privacy_rating': data_compliance.get('privacy_rating'),
                'summary': data_compliance.get('summary'),
                'evidence_refs': data_compliance.get('evidence_refs', [])
            },
            'deployment_controls': {
                'not_applicable': deployment_controls.get('not_applicable', False),
                'reason': deployment_controls.get('reason'),
                'data_source': deployment_controls.get('data_source'),
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
            'sources': self._compile_sources(product_data, security_data, virustotal_data),
            'evidence_summary': evidence_summary,
            'citations': citations
        }
        
        # Add VirusTotal data if available
        if virustotal_data:
            assessment['virustotal'] = {
                'file_hash': {
                    'sha1': virustotal_data.get('sha1'),
                    'sha256': virustotal_data.get('sha256'),
                    'md5': virustotal_data.get('md5')
                },
                'file_info': {
                    'primary_name': virustotal_data.get('primary_name'),
                    'names': virustotal_data.get('names', [])[:5],  # Limit to 5 names
                    'type': virustotal_data.get('type'),
                    'size': virustotal_data.get('size'),
                    'last_analysis_date': virustotal_data.get('last_analysis_date')
                },
                'detection': {
                    'ratio': virustotal_data.get('detection_ratio'),
                    'stats': virustotal_data.get('detection_stats', {}),
                    'malicious': virustotal_data.get('detection_stats', {}).get('malicious', 0),
                    'suspicious': virustotal_data.get('detection_stats', {}).get('suspicious', 0),
                    'undetected': virustotal_data.get('detection_stats', {}).get('undetected', 0),
                    'harmless': virustotal_data.get('detection_stats', {}).get('harmless', 0)
                },
                'signature': virustotal_data.get('signature'),
                'threat_classification': virustotal_data.get('threat_classification'),
                'tags': virustotal_data.get('tags', []),
                'source_url': virustotal_data.get('source_url')
            }
        
        return assessment
    
    def _compile_sources(self, product_data: Optional[Dict], security_data: Dict, virustotal_data: Optional[Dict] = None) -> list:
        """Compile list of data sources with timestamps"""
        
        sources = []
        
        # VirusTotal should be first if available (primary source for SHA1 lookups)
        if virustotal_data:
            sources.append({
                'name': 'VirusTotal',
                'type': 'File Analysis & Threat Intelligence',
                'url': virustotal_data.get('source_url'),
                'description': f"File hash analysis with {virustotal_data.get('detection_ratio', '0/0')} detection ratio",
                'timestamp': datetime.now().isoformat()
            })
        
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
    
    def get_assessment_by_id(self, assessment_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific cached assessment by ID"""
        return self.cache.get_assessment_by_id(assessment_id)
    
    def assess_alternative(self, product_name: str, vendor: str = None) -> Dict[str, Any]:
        """
        Lightweight assessment of an alternative product for scoring comparison.
        Returns trust score and key metrics without full UI-level details.
        
        Args:
            product_name: Name of the alternative product
            vendor: Vendor/company name (optional)
            
        Returns:
            Dict with trust_score and security metrics
        """
        
        try:
            # Gather security data (CVE, KEV, EPSS)
            security_data = self._gather_security_data(vendor, product_name)
            
            # Calculate trust score using same CVSS+EPSS+KEV formula
            scoring_data = {
                'cves': security_data['cves'],
                'kevs': security_data['kevs'],
                'epss_data': security_data.get('epss_data', [])
            }
            
            trust_score = self.trust_scorer.calculate_trust_score(scoring_data)
            
            return {
                'product_name': product_name,
                'vendor': vendor,
                'trust_score': trust_score.get('score', 0),
                'risk_level': trust_score.get('risk_level', 'unknown'),
                'cve_count': len(security_data['cves']),
                'kev_count': len(security_data['kevs']),
                'scoring_breakdown': trust_score.get('scoring_breakdown', {}),
                'key_factors': trust_score.get('key_factors', [])
            }
            
        except Exception as e:
            return {
                'product_name': product_name,
                'vendor': vendor,
                'trust_score': None,
                'risk_level': 'unknown',
                'error': str(e)
            }
