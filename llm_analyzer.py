"""
LLM integration using Google Gemini for analysis and synthesis
"""
from google import genai
from google.genai import types
import logging
from typing import Dict, Any, List, Optional
import json

logger = logging.getLogger(__name__)


class GeminiAnalyzer:
    """Use Gemini LLM for security analysis and synthesis"""
    
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash-exp"):
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.generation_config = types.GenerateContentConfig(
            temperature=0.1,  # Low temperature for factual, consistent responses
            top_p=0.95,
            top_k=40,
            max_output_tokens=4096,
        )
    
    def resolve_entity(self, input_text: str, product_hunt_data: Optional[Dict] = None, evidence_registry=None) -> Dict[str, Any]:
        """Resolve product name, vendor, and URL from input"""
        
        context = ""
        evidence_refs = []
        
        if product_hunt_data:
            context = f"\n\nProductHunt Data:\n{json.dumps(product_hunt_data, indent=2)}"
            if evidence_registry:
                ev_id = evidence_registry.add_mixed_claim(
                    source_name="ProductHunt",
                    claim_text=f"Product info: {product_hunt_data.get('name')} - {product_hunt_data.get('description', '')}",
                    url=product_hunt_data.get('url'),
                    confidence="medium"
                )
                evidence_refs.append(ev_id)
        
        prompt = f"""You are a security analyst helping to identify software products and vendors.

Given the following input: "{input_text}"
{context}

IMPORTANT: Use ONLY the information provided above. Do not invent or assume details.
If information is missing or uncertain, clearly indicate this in the confidence level.

Determine if the input refers to:
- A specific PRODUCT (e.g., "Chrome browser", "Windows 11", "MySQL database")
- A VENDOR/COMPANY only (e.g., "Microsoft", "Google", "Oracle")

Extract and identify:
1. Product Name (official name) - SET TO null IF INPUT IS VENDOR-ONLY
2. Vendor/Company Name
3. Primary Website URL (if available)
4. Alternative names or aliases

Examples:
- Input "Chrome" → product_name: "Google Chrome", vendor: "Google"
- Input "Microsoft" → product_name: null, vendor: "Microsoft"
- Input "Adobe Photoshop" → product_name: "Adobe Photoshop", vendor: "Adobe"

Respond in JSON format:
{{
    "product_name": "exact product name or null for vendor-only",
    "vendor": "company or vendor name",
    "url": "primary website URL or null",
    "aliases": ["alternative names"],
    "confidence": "high|medium|low",
    "evidence_refs": {json.dumps(evidence_refs)}
}}

Be precise and use official names. If information is uncertain, mark confidence as low."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            # Extract JSON from response
            text = response.text.strip()
            # Remove markdown code blocks if present
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            
            # Ensure evidence_refs are included
            if "evidence_refs" not in result:
                result["evidence_refs"] = evidence_refs
                
            return result
            
        except Exception as e:
            logger.error(f"Error in entity resolution: {e}")
            # Fallback: return input as-is
            return {
                "product_name": input_text,
                "vendor": "Unknown",
                "url": None,
                "aliases": [],
                "confidence": "low",
                "evidence_refs": evidence_refs
            }
    
    def classify_software(self, entity_info: Dict, product_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Classify the software into taxonomy"""
        
        product_name = entity_info.get('product_name')
        vendor = entity_info.get('vendor')
        is_vendor_only = not product_name
        
        if is_vendor_only:
            context = f"Vendor: {vendor} (Vendor-level assessment - no specific product)"
        else:
            context = f"Product: {product_name}\nVendor: {vendor}"
        
        if product_data:
            context += f"\n\nAdditional Info:\n"
            context += f"Description: {product_data.get('description', 'N/A')}\n"
            context += f"Topics: {', '.join(product_data.get('topics', []))}\n"
        
        prompt = f"""You are a security analyst classifying software products and vendors.

{context}

{'IMPORTANT: This is a VENDOR-ONLY assessment. Classify based on the vendor company type and primary business focus.' if is_vendor_only else 'Classify this software into appropriate categories.'}

Use these taxonomy categories:
- SaaS Application (specify type: CRM, Communication, Productivity, etc.)
- GenAI/ML Tool
- Developer Tool
- Security Tool
- Infrastructure/Cloud Service
- File Sharing/Storage
- Collaboration Platform
- Endpoint Agent/Software
- Browser Extension
- Mobile Application
- Operating System / Platform
- Enterprise Software Vendor
- Cloud Provider
- Technology Company
- Other (specify)

Respond in JSON format:
{{
    "primary_category": "main category",
    "sub_category": "specific type",
    "additional_categories": ["other relevant categories"],
    "use_cases": ["typical use cases"],
    "deployment_model": "SaaS|On-Premise|Hybrid|Mobile|Extension|Cloud|Various",
    "confidence": "high|medium|low"
}}"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            return result
            
        except Exception as e:
            logger.error(f"Error in classification: {e}")
            return {
                "primary_category": "Unknown",
                "sub_category": "Unknown",
                "additional_categories": [],
                "use_cases": [],
                "deployment_model": "Unknown",
                "confidence": "low"
            }
    
    def analyze_vulnerabilities(self, cve_data: List[Dict], kev_data: List[Dict], evidence_registry=None) -> Dict[str, Any]:
        """Analyze CVE and KEV data to provide vulnerability summary"""
        
        evidence_refs = []
        
        # Add CVE evidence to registry
        if evidence_registry and cve_data:
            ev_id = evidence_registry.add_independent_claim(
                source_name="NVD (National Vulnerability Database)",
                claim_text=f"Found {len(cve_data)} CVE vulnerabilities",
                url="https://nvd.nist.gov",
                confidence="high",
                metadata={"cve_count": len(cve_data)}
            )
            evidence_refs.append(ev_id)
        
        # Add KEV evidence to registry
        if evidence_registry and kev_data:
            ev_id = evidence_registry.add_independent_claim(
                source_name="CISA KEV",
                claim_text=f"Found {len(kev_data)} known exploited vulnerabilities",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                confidence="high",
                metadata={"kev_count": len(kev_data)}
            )
            evidence_refs.append(ev_id)
        
        # Check for sufficient data
        if not cve_data and not kev_data:
            return {
                "trend": "insufficient_data",
                "critical_findings": [],
                "severity_distribution": {},
                "exploitation_risk": "unknown",
                "key_concerns": ["Insufficient public evidence - no CVE or KEV data available"],
                "positive_signals": [],
                "recommendation": "Unable to assess - insufficient public evidence",
                "evidence_quality": "insufficient",
                "evidence_refs": evidence_refs
            }
        
        # Prepare data summary
        cve_summary = f"Total CVEs found: {len(cve_data)}\n"
        if cve_data:
            cve_summary += "\nRecent/Critical CVEs:\n"
            for cve in cve_data[:10]:  # Limit to top 10
                cve_summary += f"- {cve.get('cve_id')}: {cve.get('severity')} severity\n"
                cve_summary += f"  {cve.get('summary', '')[:200]}...\n"
        
        kev_summary = f"\nKnown Exploited Vulnerabilities (KEV): {len(kev_data)}\n"
        if kev_data:
            for kev in kev_data[:5]:  # Limit to top 5
                kev_summary += f"- {kev.get('cve_id')}: {kev.get('vulnerability_name')}\n"
                kev_summary += f"  Added: {kev.get('date_added')}, Ransomware: {kev.get('known_ransomware')}\n"
        
        prompt = f"""You are a security analyst reviewing vulnerability data.

{cve_summary}
{kev_summary}

IMPORTANT: Base your analysis ONLY on the provided data. Do not invent or assume vulnerabilities.
All findings must be supported by the CVE/KEV data above.

Provide a concise analysis:
1. Overall vulnerability trend (improving/stable/concerning)
2. Critical findings that require immediate attention
3. Historical pattern (are vulnerabilities being patched promptly?)
4. Exploitation risk assessment

Respond in JSON format:
{{
    "trend": "improving|stable|concerning|insufficient_data",
    "critical_findings": ["list of critical issues"],
    "severity_distribution": {{"critical": N, "high": N, "medium": N, "low": N}},
    "exploitation_risk": "high|medium|low|unknown",
    "positive_signals": ["positive aspects if any"],
    "recommendation": "brief recommendation",
    "evidence_quality": "high|medium|low",
    "evidence_refs": {json.dumps(evidence_refs)}
}}

Base your analysis ONLY on the provided data. If data is insufficient, indicate in evidence_quality."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            
            # Ensure evidence_refs are included
            if "evidence_refs" not in result:
                result["evidence_refs"] = evidence_refs
            
            # Mark this as based on factual API data, not pure LLM generation
            result["data_source"] = "api_data_with_llm_analysis"
            result["data_source_note"] = f"Based on {len(cve_data)} CVEs from NVD and {len(kev_data)} KEVs from CISA. Analysis synthesized by AI."
                
            return result
            
        except Exception as e:
            logger.error(f"Error in vulnerability analysis: {e}")
            return {
                "trend": "insufficient_data",
                "critical_findings": [],
                "severity_distribution": {},
                "exploitation_risk": "unknown",
                "key_concerns": ["Unable to analyze vulnerability data"],
                "positive_signals": [],
                "recommendation": "Insufficient data for analysis",
                "evidence_quality": "low",
                "evidence_refs": evidence_refs
            }
    
    def calculate_trust_score(self, all_data: Dict[str, Any], evidence_registry=None) -> Dict[str, Any]:
        """Calculate comprehensive trust score with rationale"""
        
        evidence_refs = []
        
        # Add evidence from trust calculation factors
        if evidence_registry:
            # KEV presence is a key trust factor
            kev_data = all_data.get('known_exploited', [])
            if kev_data:
                for item in kev_data:
                    evidence_id = evidence_registry.add_independent_claim(
                        source_name="CISA KEV Catalog",
                        claim_text=f"Known Exploited Vulnerability: {item.get('cve_id', 'Unknown')} - {item.get('vulnerability_name', '')}",
                        url=item.get('source_url', ''),
                        confidence="high"
                    )
                    evidence_refs.append(evidence_id)
            
            # Vulnerability history
            vuln_data = all_data.get('vulnerabilities', [])
            if vuln_data:
                for item in vuln_data[:3]:  # Top 3 for trust
                    evidence_id = evidence_registry.add_independent_claim(
                        source_name="NVD (National Vulnerability Database)",
                        claim_text=f"CVE: {item.get('cve_id', 'Unknown')} - Severity: {item.get('severity', 'N/A')}",
                        url=item.get('source_url', ''),
                        confidence="high"
                    )
                    evidence_refs.append(evidence_id)
        
        prompt = f"""You are a CISO evaluating a software product's security posture.

Data available:
{json.dumps(all_data, indent=2)}

Calculate a Trust Score (0-100) based on:
- Vulnerability history and trend (30%)
- Known exploited vulnerabilities (25%)
- Vendor reputation and transparency (20%)
- Product maturity and adoption (15%)
- Security practices visibility (10%)

Provide detailed scoring breakdown and rationale.

Respond in JSON format:
{{
    "score": 0-100,
    "confidence": "high|medium|low",
    "rationale": "detailed explanation",
    "scoring_breakdown": {{
        "vulnerability_history": {{"score": 0-30, "reason": "..."}},
        "kev_presence": {{"score": 0-25, "reason": "..."}},
        "vendor_reputation": {{"score": 0-20, "reason": "..."}},
        "product_maturity": {{"score": 0-15, "reason": "..."}},
        "security_practices": {{"score": 0-10, "reason": "..."}}
    }},
    "risk_level": "critical|high|medium|low",
    "key_factors": ["positive and negative factors"],
    "data_limitations": ["what data is missing"],
    "evidence_refs": {json.dumps(evidence_refs)}
}}

Be objective and cite specific evidence. Higher scores indicate more trust/lower risk."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            
            # Ensure evidence_refs are included
            if "evidence_refs" not in result:
                result["evidence_refs"] = evidence_refs
                
            return result
            
        except Exception as e:
            logger.error(f"Error in trust score calculation: {e}")
            return {
                "score": 50,
                "confidence": "low",
                "rationale": "Unable to calculate accurate trust score due to analysis error",
                "scoring_breakdown": {},
                "risk_level": "unknown",
                "key_factors": ["Insufficient data"],
                "data_limitations": ["Analysis error occurred"],
                "evidence_refs": evidence_refs
            }
    
    def suggest_alternatives(self, entity_info: Dict, classification: Dict, 
                           trust_score: Dict, evidence_registry=None) -> List[Dict[str, Any]]:
        """Suggest safer alternatives"""
        
        evidence_refs = []
        
        # Note: Alternatives are LLM-generated suggestions, not sourced from external data
        # We document that these are AI recommendations, not factual claims
        if evidence_registry:
            evidence_id = evidence_registry.add_vendor_claim(
                source_name="AI-Generated Recommendations",
                claim_text=f"Alternative suggestions for {entity_info.get('product_name', 'unknown product')}",
                url="",
                confidence="medium"
            )
            evidence_refs.append(evidence_id)
        
        category = classification.get('primary_category', 'Unknown')
        current_score = trust_score.get('score', 50)
        
        prompt = f"""You are a security advisor suggesting alternative software.

Current Product: {entity_info.get('product_name')}
Category: {category}
Current Trust Score: {current_score}/100
Issues: {', '.join(trust_score.get('key_factors', []))}

Suggest 2-3 alternative products that:
1. Serve similar purpose
2. Have better security posture
3. Are well-established and reputable

For each alternative, provide:
- Product name and vendor
- Why it's a safer choice (specific security advantages)
- Key differentiators

Respond in JSON format:
{{
    "alternatives": [
        {{
            "product_name": "name",
            "vendor": "company",
            "rationale": "why it's safer and better",
            "security_advantages": ["specific advantages"],
            "considerations": ["things to consider"]
        }}
    ],
    "evidence_refs": {json.dumps(evidence_refs)}
}}

Only suggest real, well-known alternatives. If you cannot identify suitable alternatives, return empty list."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            
            # Ensure evidence_refs are included
            if "evidence_refs" not in result:
                result["evidence_refs"] = evidence_refs
                
            return result.get('alternatives', []), evidence_refs
            
        except Exception as e:
            logger.error(f"Error in suggesting alternatives: {e}")
            return [], evidence_refs
    
    def analyze_incidents(self, entity_info: Dict, evidence_registry=None) -> Dict[str, Any]:
        """Analyze public incidents and abuse signals"""
        
        evidence_refs = []
        
        prompt = f"""Analyze public incidents and abuse signals for: {entity_info.get('product_name')} by {entity_info.get('vendor')}

Based on publicly known information, assess:
1. Data breaches or security incidents (if any)
2. Abuse/misuse reports
3. Service outages or reliability issues
4. Public controversies related to security

Respond in JSON format:
{{
    "count": 0,
    "severity": "none|low|medium|high",
    "incidents": [],
    "rating": "excellent|good|fair|poor",
    "summary": "brief summary"
}}

If you have NO concrete information about incidents, return count: 0 and severity: "none"."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            result["evidence_refs"] = evidence_refs
            result["data_source"] = "llm_generated"
            result["data_source_warning"] = "This analysis is AI-generated based on general knowledge and may not reflect current, verified information. Verify critical details independently."
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing incidents: {e}")
            return {
                "count": 0,
                "severity": "none",
                "incidents": [],
                "rating": "unknown",
                "summary": "Unable to analyze incidents",
                "evidence_refs": evidence_refs,
                "data_source": "error"
            }
    
    def analyze_data_compliance(self, entity_info: Dict, evidence_registry=None) -> Dict[str, Any]:
        """Analyze data handling and compliance posture"""
        
        evidence_refs = []
        
        prompt = f"""Analyze data handling and compliance for: {entity_info.get('product_name')} by {entity_info.get('vendor')}

Assess:
1. GDPR compliance indicators
2. SOC 2 / ISO 27001 certifications (if known)
3. Data residency options
4. Privacy policy quality

Respond in JSON format:
{{
    "status": "compliant|partial|non-compliant|unknown",
    "certifications": [],
    "gdpr_compliant": true|false|null,
    "data_residency": "description",
    "privacy_rating": "excellent|good|fair|poor|unknown",
    "summary": "brief summary"
}}

Only include concrete information. Use "unknown" if uncertain."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            result["evidence_refs"] = evidence_refs
            result["data_source"] = "llm_generated"
            result["data_source_warning"] = "This analysis is AI-generated based on general knowledge and may not reflect current, verified information. Verify critical details independently."
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing data compliance: {e}")
            return {
                "status": "unknown",
                "certifications": [],
                "gdpr_compliant": None,
                "data_residency": "Unknown",
                "privacy_rating": "unknown",
                "summary": "Unable to analyze compliance",
                "evidence_refs": evidence_refs,
                "data_source": "error"
            }
    
    def analyze_deployment_controls(self, entity_info: Dict, classification: Dict, evidence_registry=None) -> Dict[str, Any]:
        """Analyze deployment model and admin controls"""
        
        evidence_refs = []
        
        deployment_model = classification.get('deployment_model', 'Unknown')
        
        prompt = f"""Analyze deployment and administrative controls for: {entity_info.get('product_name')} by {entity_info.get('vendor')}

Deployment Model: {deployment_model}

Assess:
1. Access control capabilities (SSO, MFA, RBAC)
2. Audit logging availability
3. Admin control granularity
4. Network security features

Respond in JSON format:
{{
    "sso_support": true|false|null,
    "mfa_support": true|false|null,
    "rbac_available": true|false|null,
    "audit_logging": true|false|null,
    "control_rating": "excellent|good|fair|poor|unknown",
    "key_features": [],
    "limitations": [],
    "summary": "brief summary"
}}

Only include verified information."""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            result["evidence_refs"] = evidence_refs
            result["data_source"] = "llm_generated"
            result["data_source_warning"] = "This analysis is AI-generated based on general knowledge and may not reflect current, verified information. Verify critical details independently."
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing deployment controls: {e}")
            return {
                "sso_support": None,
                "mfa_support": None,
                "rbac_available": None,
                "audit_logging": None,
                "control_rating": "unknown",
                "key_features": [],
                "limitations": [],
                "summary": "Unable to analyze deployment controls",
                "evidence_refs": evidence_refs,
                "data_source": "error"
            }
    
    def analyze_security_practices(self, entity_info: Dict, evidence_registry=None) -> Dict[str, Any]:
        """Analyze vendor security practices and transparency"""
        
        evidence_refs = []
        
        prompt = f"""Analyze security practices for: {entity_info.get('product_name')} by {entity_info.get('vendor')}

Assess:
1. Bug bounty program existence
2. Security disclosure policy
3. Security team visibility
4. Patch management track record
5. Provide the source of the information used for the assessment.

Respond in JSON format:
{{
    "rating": "excellent|good|fair|poor|unknown",
    "bug_bounty": true|false|null,
    "disclosure_policy": true|false|null,
    "security_team_visible": true|false|null,
    "patch_cadence": "regular|irregular|unknown",
    "summary": "brief assessment",
    "evidence_refs": "references"
}}"""
        
        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=self.generation_config
            )
            
            text = response.text.strip()
            if text.startswith("```json"):
                text = text.split("```json")[1].split("```")[0].strip()
            elif text.startswith("```"):
                text = text.split("```")[1].split("```")[0].strip()
            
            result = json.loads(text)
            result["evidence_refs"] = evidence_refs
            result["data_source"] = "llm_generated"
            result["data_source_warning"] = "This analysis is AI-generated based on general knowledge and may not reflect current, verified information. Verify critical details independently."
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing security practices: {e}")
            return {
                "rating": "unknown",
                "bug_bounty": None,
                "disclosure_policy": None,
                "security_team_visible": None,
                "patch_cadence": "unknown",
                "summary": "Unable to analyze security practices",
                "evidence_refs": evidence_refs
            }
