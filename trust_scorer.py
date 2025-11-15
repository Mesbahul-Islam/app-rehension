"""
Rule-based trust scoring system with transparent calculations
"""
from typing import Dict, Any, List
from datetime import datetime, timedelta


class TrustScorer:
    """
    Transparent rule-based trust scoring (0-100)
    Higher score = More trustworthy / Lower risk
    """
    
    # Scoring weights (must sum to 100)
    WEIGHTS = {
        "vulnerability_history": 30,
        "kev_presence": 25,
        "product_maturity": 15,
        "security_practices": 15,
        "incident_signals": 10,
        "data_compliance": 5
    }
    
    def calculate_trust_score(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate transparent rule-based trust score"""
        
        components = {}
        
        # 1. Vulnerability History (30 points)
        components["vulnerability_history"] = self._score_vulnerability_history(
            assessment_data.get('cves', [])
        )
        
        # 2. KEV Presence (25 points)
        components["kev_presence"] = self._score_kev_presence(
            assessment_data.get('kevs', [])
        )
        
        # 3. Product Maturity (15 points)
        components["product_maturity"] = self._score_product_maturity(
            assessment_data.get('product_data')
        )
        
        # 4. Security Practices (15 points)
        components["security_practices"] = self._score_security_practices(
            assessment_data.get('llm_analysis', {})
        )
        
        # 5. Incident Signals (10 points)
        components["incident_signals"] = self._score_incident_signals(
            assessment_data.get('llm_analysis', {})
        )
        
        # 6. Data Compliance (5 points)
        components["data_compliance"] = self._score_data_compliance(
            assessment_data.get('llm_analysis', {})
        )
        
        # Calculate total score
        total_score = sum(components.values())
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score)
        
        # Build detailed breakdown
        breakdown = {
            component: {
                "score": score,
                "max_points": self.WEIGHTS[component],
                "weight_percentage": self.WEIGHTS[component],  # Fixed weight
                "score_percentage": (score / self.WEIGHTS[component] * 100) if self.WEIGHTS[component] > 0 else 0,  # Dynamic score
                "explanation": self._get_component_explanation(component, score, assessment_data)
            }
            for component, score in components.items()
        }
        
        return {
            "total_score": round(total_score, 1),
            "risk_level": risk_level,
            "confidence": self._calculate_confidence(assessment_data),
            "components": breakdown,
            "calculation_method": "Rule-based weighted scoring",
            "weights": self.WEIGHTS,
            "timestamp": datetime.now().isoformat()
        }
    
    def _score_vulnerability_history(self, cves: List[Dict]) -> float:
        """Score based on CVE count and severity (0-30 points)"""
        if not cves:
            return 30.0  # No CVEs = best score
        
        total_cves = len(cves)
        
        # Count by severity
        critical = sum(1 for cve in cves if cve.get('severity') == 'CRITICAL')
        high = sum(1 for cve in cves if cve.get('severity') == 'HIGH')
        medium = sum(1 for cve in cves if cve.get('severity') == 'MEDIUM')
        low = sum(1 for cve in cves if cve.get('severity') == 'LOW')
        
        # Weighted severity score (worse = lower score)
        severity_penalty = (critical * 4) + (high * 2) + (medium * 1) + (low * 0.5)
        
        # Recent CVEs are worse (last 2 years)
        recent_cves = 0
        two_years_ago = (datetime.now() - timedelta(days=730)).isoformat()
        for cve in cves:
            if cve.get('published_date', '') > two_years_ago:
                recent_cves += 1
        
        # Scoring logic
        if total_cves == 0:
            score = 30.0
        elif total_cves <= 5:
            score = 25.0 - (severity_penalty * 0.5)
        elif total_cves <= 20:
            score = 20.0 - (severity_penalty * 0.3)
        elif total_cves <= 50:
            score = 15.0 - (severity_penalty * 0.2)
        else:
            score = 10.0 - (severity_penalty * 0.1)
        
        # Penalize recent activity
        score -= (recent_cves * 0.5)
        
        return max(0, min(30, score))
    
    def _score_kev_presence(self, kevs: List[Dict]) -> float:
        """Score based on Known Exploited Vulnerabilities (0-25 points)"""
        if not kevs:
            return 25.0  # No KEVs = best score
        
        kev_count = len(kevs)
        
        # KEVs with ransomware are worse
        ransomware_kevs = sum(1 for kev in kevs if kev.get('known_ransomware') == 'Known')
        
        # Scoring logic (KEVs are critical)
        if kev_count == 0:
            score = 25.0
        elif kev_count == 1:
            score = 15.0
        elif kev_count <= 3:
            score = 10.0
        elif kev_count <= 5:
            score = 5.0
        else:
            score = 0.0
        
        # Extra penalty for ransomware
        score -= (ransomware_kevs * 2)
        
        return max(0, min(25, score))
    
    def _score_product_maturity(self, product_data: Dict) -> float:
        """Score based on product age and adoption (0-15 points)"""
        if not product_data:
            return 7.5  # Unknown = middle score
        
        score = 10.0  # Base score
        
        # More votes/comments = more mature
        votes = product_data.get('votes', 0)
        if votes > 1000:
            score += 5.0
        elif votes > 500:
            score += 3.0
        elif votes > 100:
            score += 1.0
        
        return min(15, score)
    
    def _score_security_practices(self, llm_analysis: Dict) -> float:
        """Score based on LLM analysis of security practices (0-15 points)"""
        # This will be based on LLM's assessment of security practices
        # For now, return middle score if no data
        practices = llm_analysis.get('security_practices', {})
        
        if not practices:
            return 7.5
        
        # LLM provides rating: excellent/good/fair/poor
        rating = practices.get('rating', 'unknown')
        
        rating_map = {
            'excellent': 15.0,
            'good': 12.0,
            'fair': 8.0,
            'poor': 3.0,
            'unknown': 7.5
        }
        
        return rating_map.get(rating, 7.5)
    
    def _score_incident_signals(self, llm_analysis: Dict) -> float:
        """Score based on public incidents and abuse signals (0-10 points)"""
        incidents = llm_analysis.get('incidents', {})
        
        if not incidents:
            return 10.0  # No incidents = best score
        
        incident_count = incidents.get('count', 0)
        severity = incidents.get('severity', 'none')
        
        if incident_count == 0 or severity == 'none':
            return 10.0
        elif severity == 'low':
            return 8.0
        elif severity == 'medium':
            return 5.0
        elif severity == 'high':
            return 2.0
        else:
            return 0.0
    
    def _score_data_compliance(self, llm_analysis: Dict) -> float:
        """Score based on data handling and compliance (0-5 points)"""
        compliance = llm_analysis.get('data_compliance', {})
        
        if not compliance:
            return 2.5  # Unknown = middle score
        
        # LLM provides: compliant/partial/non-compliant/unknown
        status = compliance.get('status', 'unknown')
        
        status_map = {
            'compliant': 5.0,
            'partial': 3.0,
            'non-compliant': 0.0,
            'unknown': 2.5
        }
        
        return status_map.get(status, 2.5)
    
    def _determine_risk_level(self, score: float) -> str:
        """Determine risk level based on total score"""
        if score >= 80:
            return "low"
        elif score >= 60:
            return "medium"
        elif score >= 40:
            return "high"
        else:
            return "critical"
    
    def _calculate_confidence(self, assessment_data: Dict) -> str:
        """Calculate confidence in the assessment"""
        # High confidence if we have multiple data sources
        has_cves = len(assessment_data.get('cves', [])) > 0
        has_kevs = len(assessment_data.get('kevs', [])) > 0
        has_product_data = assessment_data.get('product_data') is not None
        
        data_sources = sum([has_cves, has_kevs, has_product_data])
        
        if data_sources >= 2:
            return "high"
        elif data_sources == 1:
            return "medium"
        else:
            return "low"
    
    def _get_component_explanation(self, component: str, score: float, data: Dict) -> str:
        """Generate human-readable explanation for component score"""
        
        max_score = self.WEIGHTS[component]
        percentage = (score / max_score * 100) if max_score > 0 else 0
        
        explanations = {
            "vulnerability_history": self._explain_vuln_history(score, data.get('cves', [])),
            "kev_presence": self._explain_kev(score, data.get('kevs', [])),
            "product_maturity": self._explain_maturity(score, data.get('product_data')),
            "security_practices": f"Security practices assessment contributed {score:.1f}/{max_score} points",
            "incident_signals": f"Incident and abuse signals contributed {score:.1f}/{max_score} points",
            "data_compliance": f"Data handling and compliance contributed {score:.1f}/{max_score} points"
        }
        
        return explanations.get(component, f"Scored {score:.1f}/{max_score} points ({percentage:.0f}%)")
    
    def _explain_vuln_history(self, score: float, cves: List[Dict]) -> str:
        """Explain vulnerability history score"""
        total = len(cves)
        if total == 0:
            return f"No CVEs found - received maximum {score:.1f}/30 points"
        
        critical = sum(1 for cve in cves if cve.get('severity') == 'CRITICAL')
        high = sum(1 for cve in cves if cve.get('severity') == 'HIGH')
        
        return f"{total} CVEs found ({critical} critical, {high} high severity) - scored {score:.1f}/30 points"
    
    def _explain_kev(self, score: float, kevs: List[Dict]) -> str:
        """Explain KEV score"""
        total = len(kevs)
        if total == 0:
            return f"No known exploited vulnerabilities - received maximum {score:.1f}/25 points"
        
        ransomware = sum(1 for kev in kevs if kev.get('known_ransomware') == 'Known')
        
        if ransomware > 0:
            return f"{total} KEVs found (including {ransomware} used in ransomware) - scored {score:.1f}/25 points"
        return f"{total} known exploited vulnerabilities found - scored {score:.1f}/25 points"
    
    def _explain_maturity(self, score: float, product_data: Dict) -> str:
        """Explain product maturity score"""
        if not product_data:
            return f"Limited product data available - scored {score:.1f}/15 points"
        
        votes = product_data.get('votes', 0)
        return f"Product has {votes} votes indicating adoption level - scored {score:.1f}/15 points"
