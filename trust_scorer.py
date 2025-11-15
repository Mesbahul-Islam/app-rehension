"""
Rule-based trust scoring system with transparent calculations
"""
from typing import Dict, Any, List
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


class TrustScorer:
    """
    Trust scoring based on CVSS, EPSS, and KEV (0-100)
    Higher score = More trustworthy / Lower risk
    
    Formula:
    - CVSS weight: 50%
    - EPSS weight: 40%
    - KEV weight: 10%
    
    trust_score = (1 - risk_score) * 100
    where risk_score = 0.5*cvss_norm + 0.4*epss + 0.1*kev_flag
    """
    
    def calculate_trust_score(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate trust score based on CVSS, EPSS, and KEV
        
        Returns score from 0-100 where higher = safer
        """
        
        cves = assessment_data.get('cves', [])
        kevs = assessment_data.get('kevs', [])
        epss_data = assessment_data.get('epss_data', {})
        
        # Log incoming data
        print(f"\n=== TRUST SCORE CALCULATION ===")
        print(f"Total CVEs: {len(cves)}")
        print(f"Total KEVs: {len(kevs)}")
        print(f"EPSS data entries: {len(epss_data)}")
        print(f"EPSS data keys: {list(epss_data.keys()) if epss_data else 'None'}")
        
        if not cves:
            # No CVEs found - could mean no vulnerabilities OR insufficient data
            return {
                "score": None,  # Indicate insufficient data
                "risk_level": "UNKNOWN",
                "confidence": "Low",
                "rationale": "Insufficient data: No CVE records found. This could mean the product is very new, not widely analyzed, or not in public vulnerability databases.",
                "insufficient_data": True,
                "scoring_breakdown": {
                    "cvss_risk": None,
                    "epss_risk": None,
                    "kev_risk": 0,
                    "total_risk": None
                },
                "key_factors": ["No vulnerability data available"],
                "data_limitations": ["No CVE records found in NVD database", "Cannot calculate reliable trust score without vulnerability history"]
            }
        
        # Calculate aggregate risk metrics
        cvss_scores = []
        epss_scores = []
        kev_count = len(kevs)
        total_cves = len(cves)
        
        # Extract CVSS scores from CVEs
        for cve in cves:
            cvss = cve.get('cvss_v3') or cve.get('cvss_v2')
            if cvss:
                cvss_scores.append(float(cvss))
        
        print(f"CVSS scores extracted: {cvss_scores}")
        
        # Extract EPSS scores from epss_data
        for cve in cves:
            cve_id = cve.get('cve_id')
            print(f"Processing CVE: {cve_id}")
            if cve_id and cve_id in epss_data:
                epss = epss_data[cve_id].get('epss', 0)
                print(f"  Found EPSS: {epss}")
                epss_scores.append(float(epss))
            else:
                print(f"  No EPSS data found")
        
        print(f"EPSS scores extracted: {epss_scores}")
        
        # Calculate average CVSS (normalized to 0-1)
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 5.0  # Default to medium
        cvss_norm = avg_cvss / 10.0
        
        # Calculate average EPSS (already 0-1)
        avg_epss = sum(epss_scores) / len(epss_scores) if epss_scores else 0.1  # Default low
        
        # KEV flag (0 or 1)
        kev_flag = 1 if kev_count > 0 else 0
        
        # Calculate weighted risk score
        risk_score = (
            0.5 * cvss_norm +    # 50% weight on CVSS
            0.4 * avg_epss +     # 40% weight on EPSS
            0.1 * kev_flag       # 10% weight on KEV
        )
        
        print(f"\nScoring breakdown:")
        print(f"  Avg CVSS: {avg_cvss:.2f} (normalized: {cvss_norm:.3f})")
        print(f"  Avg EPSS: {avg_epss:.3f}")
        print(f"  KEV flag: {kev_flag}")
        print(f"  Risk score: {risk_score:.3f}")
        
        # Convert to trust score (invert risk)
        trust_score = (1 - risk_score) * 100
        trust_score = max(0, min(100, trust_score))  # Clamp to 0-100
        
        print(f"  Trust score: {trust_score:.1f}")
        print(f"==========================\n")
        
        # Determine risk level
        risk_level = self._determine_risk_level(trust_score)
        
        # Build rationale
        rationale = self._build_rationale(trust_score, avg_cvss, avg_epss, kev_count, total_cves)
        
        # Key factors
        key_factors = []
        if avg_cvss >= 7.0:
            key_factors.append(f"High average CVSS score: {avg_cvss:.1f}")
        if avg_epss >= 0.5:
            key_factors.append(f"High exploit probability: {avg_epss*100:.1f}%")
        if kev_count > 0:
            key_factors.append(f"{kev_count} known exploited vulnerability(ies)")
        if not key_factors:
            key_factors.append("Low risk profile")
        
        # Data limitations
        data_limitations = []
        if len(cvss_scores) < total_cves:
            data_limitations.append(f"CVSS data missing for {total_cves - len(cvss_scores)} CVEs")
        if len(epss_scores) < total_cves:
            data_limitations.append(f"EPSS data missing for {total_cves - len(epss_scores)} CVEs")
        
        return {
            "score": round(trust_score, 1),
            "risk_level": risk_level,
            "confidence": self._calculate_confidence(cvss_scores, epss_scores, total_cves),
            "rationale": rationale,
            "scoring_breakdown": {
                "cvss_risk": round(cvss_norm, 3),
                "epss_risk": round(avg_epss, 3),
                "kev_risk": kev_flag,
                "total_risk": round(risk_score, 3),
                "avg_cvss": round(avg_cvss, 2),
                "avg_epss": round(avg_epss, 3),
                "kev_count": kev_count,
                "total_cves": total_cves
            },
            "key_factors": key_factors,
            "data_limitations": data_limitations if data_limitations else ["None"],
            "calculation_method": "CVSS (50%) + EPSS (40%) + KEV (10%)"
        }
    
    def _determine_risk_level(self, trust_score: float) -> str:
        """Determine risk level from trust score"""
        if trust_score >= 80:
            return "VERY_LOW"
        elif trust_score >= 60:
            return "LOW"
        elif trust_score >= 40:
            return "MEDIUM"
        elif trust_score >= 20:
            return "HIGH"
        else:
            return "CRITICAL"
    
    def _build_rationale(self, trust_score: float, avg_cvss: float, avg_epss: float, kev_count: int, total_cves: int) -> str:
        """Build human-readable rationale"""
        if trust_score >= 80:
            return f"Low risk profile with {total_cves} CVE(s), average CVSS {avg_cvss:.1f}, and low exploit probability."
        elif trust_score >= 60:
            return f"Moderate risk with {total_cves} CVE(s) found, average CVSS {avg_cvss:.1f}. Monitor for updates."
        elif trust_score >= 40:
            return f"Elevated risk with {total_cves} CVE(s), average CVSS {avg_cvss:.1f}, and {kev_count} known exploit(s)."
        elif trust_score >= 20:
            return f"High risk: {total_cves} CVE(s) with average CVSS {avg_cvss:.1f} and {kev_count} actively exploited."
        else:
            return f"Critical risk: {total_cves} CVE(s) with severe CVSS scores and {kev_count} active exploits. Immediate action required."
    
    def _calculate_confidence(self, cvss_scores: List[float], epss_scores: List[float], total_cves: int) -> str:
        """Calculate confidence level based on data completeness"""
        if total_cves == 0:
            return "High"
        
        cvss_coverage = len(cvss_scores) / total_cves if total_cves > 0 else 0
        epss_coverage = len(epss_scores) / total_cves if total_cves > 0 else 0
        
        avg_coverage = (cvss_coverage + epss_coverage) / 2
        
        if avg_coverage >= 0.8:
            return "High"
        elif avg_coverage >= 0.5:
            return "Medium"
        else:
            return "Low"
    
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
