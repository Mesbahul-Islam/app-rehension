"""
Multi-agent LLM architecture using LangChain v1.0
- Research Agent: Generates initial analysis with citations
- Verification Agent: Cross-checks facts, validates URLs, and verifies claims
- Synthesis Agent: Compiles final verified report
"""
import json
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
import google.genai.types as types


class ProgressCallback:
    """Callback for tracking multi-agent progress"""
    
    def __init__(self, callback_fn: Optional[Callable] = None):
        self.callback_fn = callback_fn
        self.current_stage = None
        self.total_stages = 3
        self.stage_progress = {}
    
    def update(self, stage: str, status: str, details: str = ""):
        """Update progress and notify callback"""
        self.current_stage = stage
        self.stage_progress[stage] = {"status": status, "details": details}
        
        if self.callback_fn:
            self.callback_fn({
                "stage": stage,
                "status": status,
                "details": details,
                "progress": self.stage_progress
            })

class MultiAgentAnalyzer:
    """
    Orchestrates multiple specialized agents for security assessment:
    1. Research Agent: Initial data analysis and report generation
    2. Verification Agent: Fact-checking and cross-validation
    3. Synthesis Agent: Final report compilation with confidence scores
    """
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash-exp"):
        """Initialize multi-agent system with LangChain v1.0"""
        
        
        self.api_key = api_key
        self.model_name = model
        
        # Generation config for consistency
        self.generation_config = types.GenerateContentConfig(
            temperature=0.1,
            top_p=0.95,
            top_k=40,
            max_output_tokens=4096,
        )
        
        # Initialize research agent
        self.research_agent = self._create_research_agent()
        
        # Initialize verification agent
        self.verification_agent = self._create_verification_agent()
        
        # Initialize synthesis agent
        self.synthesis_agent = self._create_synthesis_agent()
        

    def _create_model(self) -> ChatGoogleGenerativeAI:
        """Create a Gemini model instance"""
        return ChatGoogleGenerativeAI(
            model=self.model_name,
            google_api_key=self.api_key,
            temperature=0.1,
            max_output_tokens=4096
        )
    
    def _create_research_agent(self):
        """
        Research Agent: Generates initial analysis from raw data
        Role: Deep analysis, pattern recognition, initial conclusions WITH CITATIONS
        """
        
        @tool
        def analyze_vulnerability_data(cve_data_json: str, kev_data_json: str) -> str:
            """
            Analyze CVE and KEV data to identify patterns and risks. MUST cite specific CVE IDs.
            
            Args:
                cve_data_json: JSON string containing CVE data
                kev_data_json: JSON string containing KEV data
                
            Returns:
                JSON string with vulnerability analysis including trends, severity breakdown, and citations
            """
            try:
                cves = json.loads(cve_data_json) if isinstance(cve_data_json, str) else cve_data_json
                kevs = json.loads(kev_data_json) if isinstance(kev_data_json, str) else kev_data_json
                
                # Severity breakdown
                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
                for cve in cves:
                    severity = cve.get('severity', 'UNKNOWN')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                # Year-over-year trend
                cve_by_year = {}
                for cve in cves:
                    pub_date = cve.get('published_date', '')
                    if pub_date:
                        year = pub_date[:4]
                        cve_by_year[year] = cve_by_year.get(year, 0) + 1
                
                # Critical CVE details
                critical_cves = [
                    {
                        "cve_id": cve.get('cve_id'),
                        "cvss": cve.get('cvss_v3'),
                        "summary": cve.get('summary', '')[:200],
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('cve_id')}"
                    }
                    for cve in cves if cve.get('severity') in ['CRITICAL', 'HIGH']
                ][:10]
                
                # KEV analysis
                kev_details = [
                    {
                        "cve_id": kev.get('cve_id'),
                        "vulnerability_name": kev.get('vulnerability_name'),
                        "date_added": kev.get('date_added'),
                        "ransomware": kev.get('known_ransomware', 'Unknown'),
                        "url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={kev.get('cve_id')}"
                    }
                    for kev in kevs
                ]
                
                analysis = {
                    "total_cves": len(cves),
                    "total_kevs": len(kevs),
                    "severity_breakdown": severity_counts,
                    "trend_by_year": dict(sorted(cve_by_year.items())),
                    "critical_vulnerabilities": critical_cves,
                    "known_exploited_vulnerabilities": kev_details,
                    "risk_assessment": {
                        "has_critical": severity_counts.get('CRITICAL', 0) > 0,
                        "has_kevs": len(kevs) > 0,
                        "exploitation_risk": "HIGH" if len(kevs) > 0 else "MEDIUM" if severity_counts.get('CRITICAL', 0) > 0 else "LOW"
                    }
                }
                
                return json.dumps(analysis, indent=2)
                
            except Exception as e:
                return json.dumps({"error": str(e), "cve_count": 0, "kev_count": 0})
        
        @tool
        def assess_security_practices(entity_info_json: str, security_practices_json: str) -> str:
            """
            Assess vendor security practices and transparency. MUST include URLs to evidence.
            
            Args:
                entity_info_json: JSON string with entity information
                security_practices_json: JSON string with security practices data
                
            Returns:
                JSON string with security practices assessment and evidence URLs
            """
            try:
                entity = json.loads(entity_info_json) if isinstance(entity_info_json, str) else entity_info_json
                practices = json.loads(security_practices_json) if isinstance(security_practices_json, str) else security_practices_json
                
                vendor = entity.get('vendor', 'Unknown')
                product = entity.get('product_name', 'Unknown')
                
                # Extract security indicators
                assessment = {
                    "vendor": vendor,
                    "product": product,
                    "security_indicators": {
                        "bug_bounty": practices.get('bug_bounty', 'unknown'),
                        "disclosure_policy": practices.get('disclosure_policy', 'unknown'),
                        "security_team_visible": practices.get('security_team_visible', False),
                        "patch_cadence": practices.get('patch_cadence', 'unknown'),
                        "overall_rating": practices.get('rating', 'unknown')
                    },
                    "evidence_urls": [],
                    "transparency_score": "medium"
                }
                
                # Generate evidence URLs
                if entity.get('url'):
                    base_url = entity['url'].rstrip('/')
                    assessment['evidence_urls'].extend([
                        f"{base_url}/security",
                        f"{base_url}/trust",
                        f"{base_url}/responsible-disclosure",
                        f"{base_url}/security-practices"
                    ])
                
                # Assess transparency
                indicators_found = sum(1 for v in assessment['security_indicators'].values() if v not in ['unknown', False, None])
                if indicators_found >= 4:
                    assessment['transparency_score'] = "high"
                elif indicators_found >= 2:
                    assessment['transparency_score'] = "medium"
                else:
                    assessment['transparency_score'] = "low"
                
                assessment['summary'] = practices.get('summary', 'Security practices information available')
                
                return json.dumps(assessment, indent=2)
                
            except Exception as e:
                return json.dumps({"error": str(e), "transparency_score": "unknown"})
        
        agent = create_agent(
            model=self._create_model(),
            tools=[analyze_vulnerability_data, assess_security_practices],
            system_prompt="""You are a Security Research Analyst with deep expertise in vulnerability analysis.

Your role:
1. Analyze all provided data thoroughly (CVEs, KEVs, vendor info, compliance)
2. Identify patterns, trends, and potential risks
3. Generate detailed findings with specific evidence
4. Provide initial assessments and recommendations

CRITICAL CITATION REQUIREMENTS:
- EVERY claim MUST be cited with a specific source
- For CVEs: cite CVE ID and NVD URL (https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXX)
- For KEVs: cite CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- For vendor claims: cite official vendor URLs (documentation, security pages)
- For third-party info: cite source URLs (news articles, security advisories)

OUTPUT FORMAT - MANDATORY:
{
  "findings": [
    {
      "claim": "Specific factual claim",
      "severity": "high|medium|low",
      "source_type": "independent|vendor|mixed",
      "citations": [
        {
          "source": "Source name (e.g., NVD, CISA, Vendor Security Page)",
          "url": "Full URL to evidence",
          "quote": "Relevant quote or data point",
          "accessed": "Date accessed"
        }
      ],
      "confidence": "high|medium|low"
    }
  ],
  "summary": "Overall assessment",
  "uncited_assumptions": ["List any assumptions without direct evidence"]
}

RULES:
- NO claim without citation
- If you cannot find a citation, mark as "uncited_assumptions"
- Include full URLs, not truncated
- Be thorough but objective
- Highlight both positive and negative findings

You are the FIRST stage - generate comprehensive initial analysis WITH ALL CITATIONS."""
        )
        
        return agent
    
    def _create_verification_agent(self):
        """
        Verification Agent: Cross-checks research agent findings AND validates URLs
        Role: Fact-checking, URL verification, validation, confidence scoring
        """
        
        @tool
        def verify_url(url: str) -> str:
            """
            Verify that a URL is accessible and returns valid content.
            
            Args:
                url: The URL to verify
                
            Returns:
                JSON string with verification status, status code, and any redirects
            """
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Security Assessment Bot)'}
                response = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
                
                result = {
                    "url": url,
                    "status": "accessible" if response.status_code == 200 else "error",
                    "status_code": response.status_code,
                    "redirected": response.url != url,
                    "final_url": response.url if response.url != url else None,
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status_code == 200:
                    result["message"] = "✓ URL accessible"
                elif response.status_code in [301, 302, 307, 308]:
                    result["message"] = f"⚠ URL redirected to {response.url}"
                elif response.status_code == 404:
                    result["message"] = "✗ URL not found (404)"
                else:
                    result["message"] = f"⚠ URL returned status {response.status_code}"
                
                return json.dumps(result, indent=2)
                
            except requests.exceptions.Timeout:
                return json.dumps({
                    "url": url,
                    "status": "timeout",
                    "message": "✗ URL verification timed out",
                    "timestamp": datetime.now().isoformat()
                })
            except requests.exceptions.ConnectionError:
                return json.dumps({
                    "url": url,
                    "status": "connection_error",
                    "message": "✗ Could not connect to URL",
                    "timestamp": datetime.now().isoformat()
                })
            except Exception as e:
                return json.dumps({
                    "url": url,
                    "status": "error",
                    "message": f"✗ Verification failed: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                })
        
        @tool
        def cross_check_claim(claim: str, evidence_json: str) -> str:
            """
            Verify a claim against available evidence.
            
            Args:
                claim: The claim to verify
                evidence_json: JSON string containing supporting evidence
                
            Returns:
                JSON string with verification result and confidence level
            """
            try:
                evidence = json.loads(evidence_json) if isinstance(evidence_json, str) else evidence_json
                
                # Analyze claim against evidence
                claim_lower = claim.lower()
                verification = {
                    "claim": claim,
                    "evidence_found": False,
                    "confidence": "low",
                    "supporting_data": [],
                    "contradictions": []
                }
                
                # Check for numerical claims
                import re
                numbers_in_claim = re.findall(r'\b\d+\b', claim)
                
                # Check if evidence contains supporting data
                evidence_str = json.dumps(evidence).lower()
                
                # Check for keywords match
                keywords = ['cve', 'vulnerability', 'critical', 'high', 'medium', 'low', 'exploit', 'kev']
                matching_keywords = [kw for kw in keywords if kw in claim_lower and kw in evidence_str]
                
                if matching_keywords:
                    verification['evidence_found'] = True
                    verification['supporting_data'].append(f"Keywords match: {', '.join(matching_keywords)}")
                    verification['confidence'] = "medium"
                
                # Check for numerical match
                if numbers_in_claim:
                    for num in numbers_in_claim:
                        if num in evidence_str:
                            verification['confidence'] = "high"
                            verification['supporting_data'].append(f"Numerical data confirmed: {num}")
                
                if not verification['evidence_found']:
                    verification['confidence'] = "low"
                    verification['supporting_data'].append("Limited evidence found in provided data")
                
                return json.dumps(verification, indent=2)
                
            except Exception as e:
                return json.dumps({
                    "claim": claim,
                    "error": str(e),
                    "confidence": "unknown"
                })
        
        @tool
        def validate_cve_reference(cve_id: str) -> str:
            """
            Validate that a CVE ID exists in NVD database.
            
            Args:
                cve_id: The CVE ID to validate (e.g., CVE-2024-1234)
                
            Returns:
                JSON string with validation result and NVD URL
            """
            try:
                # Validate CVE ID format
                import re
                if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                    return json.dumps({
                        "cve_id": cve_id,
                        "valid": False,
                        "message": "✗ Invalid CVE ID format",
                        "expected_format": "CVE-YYYY-NNNN"
                    })
                
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                headers = {'User-Agent': 'Mozilla/5.0 (Security Assessment Bot)'}
                
                response = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
                
                result = {
                    "cve_id": cve_id,
                    "valid": response.status_code == 200,
                    "nvd_url": url,
                    "status_code": response.status_code,
                    "timestamp": datetime.now().isoformat()
                }
                
                if response.status_code == 200:
                    result["message"] = f"✓ Valid CVE: {cve_id}"
                elif response.status_code == 404:
                    result["message"] = f"⚠ CVE not found in NVD: {cve_id}"
                else:
                    result["message"] = f"⚠ NVD returned status {response.status_code}"
                
                return json.dumps(result, indent=2)
                
            except Exception as e:
                return json.dumps({
                    "cve_id": cve_id,
                    "valid": False,
                    "message": f"✗ CVE validation failed: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                })
        
        agent = create_agent(
            model=self._create_model(),
            tools=[verify_url, cross_check_claim, validate_cve_reference],
            system_prompt="""You are a Security Verification Specialist focused on accuracy and fact-checking.

Your role:
1. Review research agent's findings critically
2. VERIFY ALL URLS - visit each citation URL to confirm accessibility
3. Cross-check every claim against provided evidence
4. Validate CVE IDs and other references
5. Identify unsubstantiated claims or over/under-statements
6. Validate severity assessments and risk ratings
7. Flag any inconsistencies or logical gaps

VERIFICATION PROCESS:
For EACH citation in the research agent's output:
1. Use verify_url tool to check URL accessibility
2. Mark URL status (accessible/broken/redirected)
3. Validate that the URL matches the claim (e.g., CVE URLs should point to NVD)
4. For CVE references, use validate_cve_reference tool

VERIFICATION CRITERIA:
- Does the claim have supporting evidence?
- Is the evidence source reliable (independent vs vendor)?
- Are ALL URLs accessible and valid?
- Is the severity rating justified by the data?
- Are there contradictions in the findings?
- What's the confidence level for this claim?

OUTPUT FORMAT - MANDATORY:
{
  "verified_claims": [
    {
      "original_claim": "Claim from research agent",
      "verification_status": "verified|partially_verified|unverified|contradicted",
      "url_checks": [
        {
          "url": "Full URL",
          "status": "accessible|broken|redirect|timeout",
          "notes": "Any issues found"
        }
      ],
      "evidence_quality": "strong|moderate|weak|none",
      "confidence_adjustment": "increase|maintain|decrease",
      "reasoning": "Why this verification decision"
    }
  ],
  "flagged_claims": [
    {
      "claim": "Claim that failed verification",
      "reason": "Why it was flagged",
      "missing_citations": ["What citations are missing"]
    }
  ],
  "confidence_adjustments": [
    {
      "finding": "Which finding",
      "original_confidence": "high|medium|low",
      "adjusted_confidence": "high|medium|low",
      "reason": "Why adjusted"
    }
  ],
  "missing_evidence": ["What evidence is missing or insufficient"]
}

CRITICAL RULES:
- Review every citation provided by research agent
- No claim passes verification without proper citations
- Flag any missing or insufficient citations
- Be strict: better to flag than miss errors

You are the SECOND stage - ensure accuracy and prevent hallucinations."""
        )
        
        return agent
    
    def _create_synthesis_agent(self):
        """
        Synthesis Agent: Compiles final verified report with validated citations
        Role: Integration, prioritization, evidence-based reporting
        """
        
        @tool
        def prioritize_findings(findings_json: str) -> str:
            """
            Prioritize findings by severity, confidence, and evidence quality.
            
            Args:
                findings_json: JSON string containing findings to prioritize
                
            Returns:
                JSON string with prioritized findings sorted by risk level
            """
            try:
                findings = json.loads(findings_json) if isinstance(findings_json, str) else findings_json
                
                # Define priority weights
                severity_weight = {
                    'critical': 10,
                    'high': 7,
                    'medium': 4,
                    'low': 2
                }
                
                confidence_weight = {
                    'high': 3,
                    'medium': 2,
                    'low': 1
                }
                
                evidence_quality_weight = {
                    'strong': 3,
                    'moderate': 2,
                    'weak': 1,
                    'none': 0
                }
                
                prioritized = []
                
                if isinstance(findings, list):
                    for finding in findings:
                        severity = finding.get('severity', 'low').lower()
                        confidence = finding.get('confidence', 'low').lower()
                        evidence_quality = finding.get('evidence_quality', 'none').lower()
                        
                        # Calculate priority score
                        score = (
                            severity_weight.get(severity, 2) +
                            confidence_weight.get(confidence, 1) +
                            evidence_quality_weight.get(evidence_quality, 0)
                        )
                        
                        finding['priority_score'] = score
                        finding['priority_level'] = 'critical' if score >= 13 else 'high' if score >= 10 else 'medium' if score >= 6 else 'low'
                        prioritized.append(finding)
                    
                    # Sort by priority score (descending)
                    prioritized.sort(key=lambda x: x['priority_score'], reverse=True)
                
                result = {
                    "prioritized_findings": prioritized,
                    "summary": {
                        "total": len(prioritized),
                        "critical_priority": len([f for f in prioritized if f.get('priority_level') == 'critical']),
                        "high_priority": len([f for f in prioritized if f.get('priority_level') == 'high']),
                        "medium_priority": len([f for f in prioritized if f.get('priority_level') == 'medium']),
                        "low_priority": len([f for f in prioritized if f.get('priority_level') == 'low'])
                    }
                }
                
                return json.dumps(result, indent=2)
                
            except Exception as e:
                return json.dumps({"error": str(e), "prioritized_findings": []})
        
        agent = create_agent(
            model=self._create_model(),
            tools=[prioritize_findings],
            system_prompt="""You are a CISO-level Security Assessment Synthesizer.

Your role:
1. Integrate research findings with verification results
2. Keep ONLY claims with verified, accessible citations
3. Remove or flag claims with broken URLs or missing evidence
4. Prioritize findings by risk impact AND evidence quality
5. Include transparent citation tracking

SYNTHESIS PRIORITIES:
- Trust verification agent's URL checks - if URL is broken, downgrade or remove claim
- Emphasize claims with "verified" status and accessible URLs
- Clearly separate:
  * VERIFIED: Claims with accessible citations (✓)
  * PARTIALLY VERIFIED: Claims with some missing/broken URLs (⚠)
  * UNVERIFIED: Claims without proper citations (✗)
- Mark each finding with evidence quality and citation status
- Include complete citation list with URL status

OUTPUT FORMAT - MANDATORY:
{
  "verified_findings": [
    {
      "finding": "The verified claim",
      "severity": "critical|high|medium|low",
      "evidence_quality": "strong|moderate|weak",
      "citations": [
        {
          "source": "Source name",
          "url": "Referenced URL",
          "quote": "Supporting quote"
        }
      ],
      "confidence": "high|medium|low"
    }
  ],
  "partially_verified_findings": [
    {
      "finding": "Claim with some issues",
      "issue": "Evidence incomplete or needs clarification",
      "citations": []
    }
  ],
  "unverified_claims": [
    {
      "claim": "Could not verify",
      "reason": "Missing citations or insufficient evidence"
    }
  ],
  "transparency_notes": [
    "Any limitations in evidence",
    "Data sources not available",
    "Assumptions made"
  ]
}

CRITICAL RULES:
- NO claim in final report without at least one accessible URL
- Clearly mark verification status (✓/⚠/✗)
- If all citations are broken, move to unverified_claims
- Prioritize verified findings over unverified
- Be transparent about evidence quality

You are the FINAL stage - produce the authoritative, citation-backed report."""
        )
        
        return agent
    
    def analyze_with_verification(
        self,
        entity_info: Dict,
        cve_data: List[Dict],
        kev_data: List[Dict],
        security_practices: Dict,
        incidents: Dict,
        data_compliance: Dict,
        deployment_controls: Dict,
        progress_callback: Optional[Callable] = None,
        virustotal_data: Optional[Dict] = None,
        is_virustotal_analysis: bool = False
    ) -> Dict[str, Any]:
        """
        Run multi-agent analysis pipeline:
        1. Research Agent generates initial analysis
        2. Verification Agent validates findings
        3. Synthesis Agent compiles final report
        """
        
        progress = ProgressCallback(progress_callback)
        
        try:
            progress.update("preparation", "in_progress", "Preparing data for multi-agent analysis")
            
            # Prepare consolidated data for agents
            analysis_data = {
                "entity": entity_info,
                "cves": cve_data[:10],  # Limit to top 10 for token management
                "kevs": kev_data[:5],   # Limit to top 5
                "security_practices": security_practices,
                "incidents": incidents,
                "data_compliance": data_compliance,
                "deployment_controls": deployment_controls
            }
            
            # Add VirusTotal data if available
            if virustotal_data:
                analysis_data["virustotal"] = virustotal_data
            
            data_str = json.dumps(analysis_data, indent=2)
            
            progress.update("preparation", "completed", "Data prepared successfully")
            
            # Stage 1: Research Agent Analysis
            progress.update("research", "in_progress", "Research Agent analyzing security data...")

            # Use different prompts based on analysis type
            if is_virustotal_analysis:
                research_prompt = self._get_virustotal_research_prompt(data_str, virustotal_data)
            else:
                research_prompt = self._get_standard_research_prompt(data_str)
            
            
            research_result = self.research_agent.invoke({
                "messages": [{"role": "user", "content": research_prompt}]
            })
            
            research_analysis = research_result["messages"][-1].content
            
            progress.update("research", "completed", "Research analysis complete with citations")

            # Stage 2: Verification Agent Review
            progress.update("verification", "in_progress", "Verification Agent validating URLs and cross-checking findings...")

            # Parse research findings to extract URLs
            research_findings = {}
            try:
                # Extract JSON from markdown code blocks if present
                research_text = research_analysis
                if "```json" in research_text:
                    research_text = research_text.split("```json")[1].split("```")[0].strip()
                elif "```" in research_text:
                    research_text = research_text.split("```")[1].split("```")[0].strip()
                research_findings = json.loads(research_text)
            except json.JSONDecodeError:
                research_findings = {"findings": [], "uncited_assumptions": [research_analysis]}
            
            # Extract all URLs for verification
            all_urls = []
            if "findings" in research_findings:
                for finding in research_findings.get("findings", []):
                    for citation in finding.get("citations", []):
                        if "url" in citation:
                            all_urls.append(citation["url"])
            
            
            verification_prompt = f"""Review this research analysis and verify all claims against the source data:

RESEARCH ANALYSIS:
{research_analysis}

SOURCE DATA:
{data_str}

CRITICAL TASKS:
1. Use verify_url tool to check accessibility of ALL cited URLs: {all_urls}
2. Cross-check EVERY claim against source data
3. Validate CVE references using validate_cve_reference tool
4. Flag any missing citations or broken URLs

Output in JSON format:
{{
  "url_checks": [
    {{"url": "...", "status": "accessible|broken|redirect", "status_code": 200}}
  ],
  "verified_claims": [],
  "disputed_claims": [],
  "missing_citations": [],
  "broken_urls": [],
  "url_verification_summary": {{
    "total_urls": 0,
    "accessible": 0,
    "broken": 0,
    "redirected": 0
  }}
}}"""
            
            
            verification_result = self.verification_agent.invoke({
                "messages": [{"role": "user", "content": verification_prompt}]
            })
            
            verification_analysis = verification_result["messages"][-1].content
            
            progress.update("verification", "completed", "URL validation and verification complete")

            # Stage 3: Synthesis Agent Final Report
            progress.update("synthesis", "in_progress", "Synthesis Agent compiling final verified report...")

            synthesis_prompt = f"""Compile final verified security assessment report with citation-based filtering:

RESEARCH FINDINGS WITH CITATIONS:
{research_analysis}

URL VERIFICATION RESULTS:
{verification_analysis}

SOURCE DATA:
{data_str}

CRITICAL REQUIREMENTS:
1. Categorize findings based on citation validity:
   - verified_findings: Claims with ALL URLs accessible (status 200)
   - partially_verified_findings: Claims with SOME broken URLs
   - unverified_claims: Claims with NO accessible citations
2. Include citations with all findings
3. NO claim in final report without proper citations

Output final assessment in JSON format:
{{
  "verified_findings": [],
  "partially_verified_findings": [],
  "unverified_claims": [],
  "data_quality_notes": []
}}"""
            
            
            synthesis_result = self.synthesis_agent.invoke({
                "messages": [{"role": "user", "content": synthesis_prompt}]
            })
            
            final_report = synthesis_result["messages"][-1].content
            
            progress.update("synthesis", "completed", "Final report generated")

            # Parse verification results to extract broken URLs
            verification_data = {}
            try:
                verification_text = verification_analysis
                if "```json" in verification_text:
                    verification_text = verification_text.split("```json")[1].split("```")[0].strip()
                elif "```" in verification_text:
                    verification_text = verification_text.split("```")[1].split("```")[0].strip()
                verification_data = json.loads(verification_text)
            except json.JSONDecodeError:
                pass
            
            # Parse final report (expect JSON)
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in final_report:
                    final_report = final_report.split("```json")[1].split("```")[0].strip()
                elif "```" in final_report:
                    final_report = final_report.split("```")[1].split("```")[0].strip()
                
                final_assessment = json.loads(final_report)
                
                # Add broken URLs from verification if not already present
                if 'broken_urls' not in final_assessment and 'broken_urls' in verification_data:
                    final_assessment['broken_urls'] = verification_data['broken_urls']
                
                # Add URL checks from verification for debugging
                if 'url_checks' in verification_data:
                    final_assessment['_url_verification_details'] = verification_data['url_checks']
                
            except json.JSONDecodeError:
                final_assessment = {
                    "analysis": final_report,
                    "format": "text",
                    "agents_used": ["research", "verification", "synthesis"]
                }
                # Still try to include broken URLs
                if 'broken_urls' in verification_data:
                    final_assessment['broken_urls'] = verification_data['broken_urls']
            
            # Add multi-agent metadata
            final_assessment["_multi_agent_metadata"] = {
                "pipeline": "research → verification → synthesis",
                "stages_completed": 3,
                "verification_applied": True,
                "confidence_validated": True
            }
            
            # Extract all citations from findings for frontend display
            all_citations = []
            
            # Extract from verified_findings
            for finding in final_assessment.get('verified_findings', []):
                for citation in finding.get('citations', []):
                    citation_obj = {
                        'source': citation.get('source', 'Unknown'),
                        'url': citation.get('url', ''),
                        'quote': citation.get('quote', ''),
                        'content': finding.get('claim', ''),  # Include the claim as context
                        'source_type': finding.get('source_type', 'unknown'),
                        'accessed': citation.get('accessed', '')
                    }
                    all_citations.append(citation_obj)
            
            # Extract from partially_verified_findings
            for finding in final_assessment.get('partially_verified_findings', []):
                for citation in finding.get('citations', []):
                    citation_obj = {
                        'source': citation.get('source', 'Unknown'),
                        'url': citation.get('url', ''),
                        'quote': citation.get('quote', ''),
                        'content': finding.get('claim', ''),
                        'source_type': finding.get('source_type', 'unknown'),
                        'accessed': citation.get('accessed', '')
                    }
                    all_citations.append(citation_obj)
            
            # Add citations to assessment for frontend display
            if all_citations:
                final_assessment['citations'] = all_citations
            
            
            return final_assessment
            
        except Exception as e:
            return {
                "error": str(e),
                "fallback_analysis": "Multi-agent pipeline failed, falling back to single-agent mode",
                "agents_used": []
            }
    
    def quick_verify_claim(self, claim: str, evidence: Dict) -> Dict[str, Any]:
        """
        Quick verification of a single claim using verification agent
        """
        
        prompt = f"""Verify this specific claim:

CLAIM: {claim}

EVIDENCE: {json.dumps(evidence, indent=2)}

Assess:
1. Is the claim supported by evidence?
2. Confidence level (high/medium/low)
3. Any contradictions or gaps?

Output in JSON format."""
        
        result = self.verification_agent.invoke({
            "messages": [{"role": "user", "content": prompt}]
        })
        
        verification = result["messages"][-1].content
        
        try:
            return json.loads(verification)
        except:
            return {"verification": verification, "format": "text"}
    
    def _get_standard_research_prompt(self, data_str: str) -> str:
        """Generate research prompt for standard product/vendor analysis"""
        return f"""Analyze this security data and generate comprehensive findings with MANDATORY citations:

{data_str}

Provide detailed analysis covering:
1. Vulnerability trends and severity assessment
2. Security practices evaluation
3. Incident history assessment
4. Compliance posture
5. Deployment security controls

CRITICAL: Every claim MUST include citations. Output in JSON format:
{{
  "findings": [
    {{
      "claim": "specific finding statement",
      "severity": "critical|high|medium|low",
      "category": "vulnerability|security_practice|incident|compliance|deployment",
      "source_type": "vendor|independent|mixed",
      "citations": [
        {{
          "source": "source name",
          "url": "full URL to reference",
          "quote": "exact quote or data point",
          "accessed": "{datetime.now().strftime('%Y-%m-%d')}"
        }}
      ]
    }}
  ],
  "uncited_assumptions": []
}}"""
    
    def _get_virustotal_research_prompt(self, data_str: str, virustotal_data: Dict) -> str:
        """Generate research prompt for VirusTotal file analysis"""
        
        detection_stats = virustotal_data.get('detection_stats', {})
        malicious = detection_stats.get('malicious', 0)
        suspicious = detection_stats.get('suspicious', 0)
        total = sum(detection_stats.values())
        
        return f"""Analyze this VirusTotal file security data and generate comprehensive findings with MANDATORY citations:

{data_str}

FILE ANALYSIS CONTEXT:
- This is a FILE HASH analysis from VirusTotal, NOT a product/vendor assessment
- Detection Ratio: {virustotal_data.get('detection_ratio', 'Unknown')}
- Malicious Detections: {malicious}/{total}
- Suspicious Detections: {suspicious}/{total}
- File Type: {virustotal_data.get('type', 'Unknown')}
- File Name: {virustotal_data.get('primary_name', 'Unknown')}

FOCUS YOUR ANALYSIS ON:
1. **Detection Analysis**: Evaluate the AV engine detection results
   - Which engines flagged it and what did they call it?
   - Are the detections consistent or conflicting?
   - What is the threat severity based on detection patterns?

2. **File Characteristics**: Assess file properties and reputation
   - Digital signature verification status
   - File age and version information
   - Multiple names (could indicate obfuscation)
   - File type risk assessment

3. **Threat Classification**: Evaluate identified threats
   - What threat categories were identified?
   - Known malware families or behaviors
   - Risk to system if executed

4. **Vendor/Publisher Trust**: Assess the file publisher
   - Is it signed by a known vendor?
   - Signature verification status
   - Publisher reputation

5. **Behavioral Indicators**: Security concerns
   - Any sandbox/dynamic analysis results
   - Known exploited vulnerabilities in this file
   - Historical incidents or campaigns using this file

DO NOT analyze:
- Product roadmap or feature sets
- Business compliance (unless related to malware behavior)
- Deployment controls (not applicable to file analysis)

CRITICAL: Every claim MUST cite VirusTotal data. Output in JSON format:
{{
  "findings": [
    {{
      "claim": "specific finding about the file",
      "severity": "critical|high|medium|low",
      "category": "detection|file_characteristics|threat_classification|vendor_trust|behavioral",
      "source_type": "independent",
      "citations": [
        {{
          "source": "VirusTotal",
          "url": "{virustotal_data.get('source_url', 'https://www.virustotal.com')}",
          "quote": "specific data point from VT analysis",
          "accessed": "{datetime.now().strftime('%Y-%m-%d')}"
        }}
      ],
      "detection_context": {{
        "av_engines_flagged": 0,
        "threat_names": []
      }}
    }}
  ],
  "analysis_type": "virustotal_file_analysis",
  "file_verdict": "clean|suspicious|malicious",
  "confidence": "high|medium|low",
  "uncited_assumptions": []
}}"""

