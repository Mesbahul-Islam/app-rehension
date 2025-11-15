"""
VirusTotal-specific trust scoring system with transparent calculations
Focused on file analysis metrics rather than product security metrics
"""
from typing import Dict, Any, List
from datetime import datetime, timedelta


class VirusTotalTrustScorer:
    """
    Transparent rule-based trust scoring for VirusTotal file analysis (0-100)
    Higher score = More trustworthy / Lower risk
    
    Different weights focused on file security indicators:
    - Detection ratio and severity
    - Signature verification
    - File age and prevalence
    - Threat classification
    - Vendor reputation
    """
    
    # Scoring weights optimized for VirusTotal data (must sum to 100)
    WEIGHTS = {
        "detection_ratio": 40,        # Primary indicator - how many AV engines flagged it
        "signature_verification": 20,  # Digital signature validity
        "file_reputation": 15,        # Based on names, age, prevalence
        "threat_classification": 15,  # Known threat types
        "vendor_trust": 10            # Publisher/vendor reputation
    }
    
    def calculate_trust_score(self, virustotal_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate transparent rule-based trust score from VirusTotal data"""
        
        components = {}
        
        # 1. Detection Ratio (40 points) - Most critical for file analysis
        components["detection_ratio"] = self._score_detection_ratio(
            virustotal_data.get('detection_stats', {}),
            virustotal_data.get('detection_ratio', '0/0')
        )
        
        # 2. Signature Verification (20 points)
        components["signature_verification"] = self._score_signature(
            virustotal_data.get('signature', {})
        )
        
        # 3. File Reputation (15 points)
        components["file_reputation"] = self._score_file_reputation(
            virustotal_data
        )
        
        # 4. Threat Classification (15 points)
        components["threat_classification"] = self._score_threat_classification(
            virustotal_data.get('threat_classification', {}),
            virustotal_data.get('tags', [])
        )
        
        # 5. Vendor Trust (10 points)
        components["vendor_trust"] = self._score_vendor_trust(
            virustotal_data.get('vendor'),
            virustotal_data.get('signature', {})
        )
        
        # Calculate total score
        total_score = sum(components.values())
        
        # Determine risk level
        risk_level = self._determine_risk_level(total_score, virustotal_data.get('detection_stats', {}))
        
        # Build detailed breakdown
        breakdown = {
            component: {
                "score": score,
                "max_points": self.WEIGHTS[component],
                "weight_percentage": self.WEIGHTS[component],
                "score_percentage": (score / self.WEIGHTS[component] * 100) if self.WEIGHTS[component] > 0 else 0,
                "explanation": self._get_component_explanation(component, score, virustotal_data)
            }
            for component, score in components.items()
        }
        
        return {
            "total_score": round(total_score, 1),
            "risk_level": risk_level,
            "confidence": self._calculate_confidence(virustotal_data),
            "components": breakdown,
            "calculation_method": "Rule-based weighted scoring for VirusTotal file analysis",
            "weights": self.WEIGHTS,
            "timestamp": datetime.now().isoformat(),
            "analysis_type": "virustotal_file_analysis"
        }
    
    def _score_detection_ratio(self, detection_stats: Dict, detection_ratio: str) -> float:
        """Score based on AV engine detection ratio (0-40 points)
        
        Uses only actual detection counts from VirusTotal API.
        Formula: 40 * (1 - (malicious + suspicious) / total_scans)
        """
        
        malicious = detection_stats.get('malicious', 0)
        suspicious = detection_stats.get('suspicious', 0)
        undetected = detection_stats.get('undetected', 0)
        harmless = detection_stats.get('harmless', 0)
        
        total_scans = malicious + suspicious + undetected + harmless
        
        if total_scans == 0:
            return 0.0  # No data = cannot assess
        
        # Calculate clean percentage (undetected + harmless)
        clean_count = undetected + harmless
        clean_percentage = (clean_count / total_scans)
        
        # Direct formula: score increases with clean percentage
        # Malicious detections have double weight vs suspicious
        weighted_detections = (malicious * 2) + suspicious
        weighted_total = total_scans + malicious  # Double count malicious
        
        score = 40.0 * (1 - (weighted_detections / weighted_total))
        
        return max(0, min(40, score))
    
    def _score_signature(self, signature: Dict) -> float:
        """Score based on digital signature verification (0-20 points)
        
        Uses only signature verification status from VirusTotal API.
        Verified = 20 points, Invalid = 0 points, No signature = 10 points
        """
        
        if not signature:
            return 10.0  # No signature data available
        
        # Check verification status (only concrete value from API)
        verified = signature.get('verified', '')
        verified_lower = str(verified).lower()
        
        # Use only the verification status from VirusTotal
        if 'valid' in verified_lower and 'invalid' not in verified_lower:
            return 20.0  # Verified valid signature
        elif 'invalid' in verified_lower:
            return 0.0   # Invalid signature
        else:
            return 10.0  # Signature exists but verification status unclear
    
    def _score_file_reputation(self, virustotal_data: Dict) -> float:
        """Score based on file characteristics (0-15 points)
        
        Uses only concrete data: file age from API.
        Newer files in VT database = less history = slightly lower score.
        """
        
        score = 15.0  # Start with full points
        
        # File age from last_analysis_date (actual API data)
        last_analysis = virustotal_data.get('last_analysis_date')
        if last_analysis:
            try:
                analysis_date = datetime.fromisoformat(last_analysis.replace('Z', '+00:00'))
                days_old = (datetime.now(analysis_date.tzinfo) - analysis_date).days
                
                # Linear penalty for newer files (less history)
                # Files < 30 days old lose up to 5 points
                if days_old < 30:
                    penalty = (30 - days_old) / 30 * 5.0
                    score -= penalty
            except:
                pass  # If date parsing fails, keep full score
        
        return max(0, min(15, score))
    
    def _score_threat_classification(self, threat_classification: Dict, tags: List[str]) -> float:
        """Score based on threat categorization (0-15 points)
        
        Uses only the suggested_threat_label from VirusTotal API.
        If no threat label exists, full points. If threat detected, zero points.
        """
        
        if not threat_classification:
            return 15.0  # No classification data = assume clean
        
        # Check threat label from API
        suggested_threat = threat_classification.get('suggested_threat_label', '')
        
        # If VirusTotal identified any threat label, score is 0
        # If no threat label, full score
        if suggested_threat and suggested_threat.strip() and suggested_threat.lower() not in ['none', 'clean', 'unknown']:
            return 0.0  # Threat identified by VirusTotal
        else:
            return 15.0  # No threat classification from VirusTotal
    
    def _score_vendor_trust(self, vendor: str, signature: Dict) -> float:
        """Score based on signature verification only (0-10 points)
        
        Uses only signature verification from API - not subjective vendor lists.
        Valid signature = 10 points, Invalid = 0, No vendor/signature = 5 points
        """
        
        # Only use signature verification status (objective API data)
        if signature:
            verified = signature.get('verified', '')
            verified_lower = str(verified).lower()
            
            if 'valid' in verified_lower and 'invalid' not in verified_lower:
                return 10.0  # Valid signature from any publisher
            elif 'invalid' in verified_lower:
                return 0.0   # Invalid signature
        
        # No signature data
        return 5.0  # Neutral score when no signature info available
    
    def _determine_risk_level(self, score: float, detection_stats: Dict) -> str:
        """Determine risk level based on total score and malicious detections
        
        Uses only the malicious count from VirusTotal API.
        Any malicious detection = at least medium risk, regardless of score.
        """
        
        # Priority override: if ANY malicious detections, minimum medium risk
        malicious = detection_stats.get('malicious', 0)
        if malicious > 0:
            # Use malicious count directly
            if malicious >= 10:
                return "critical"
            elif malicious >= 5:
                return "high"
            else:
                return "medium"  # Any malicious detection = at least medium
        
        # No malicious detections - use score-based risk levels
        if score >= 75:
            return "low"
        elif score >= 50:
            return "medium"
        elif score >= 25:
            return "high"
        else:
            return "critical"
    
    def _calculate_confidence(self, virustotal_data: Dict) -> str:
        """Calculate confidence based on number of AV engines that scanned
        
        Uses only the total scan count from VirusTotal API.
        More scanners = higher confidence in the assessment.
        """
        
        detection_stats = virustotal_data.get('detection_stats', {})
        total_scans = sum(detection_stats.values())
        
        # Confidence based solely on number of AV engines
        if total_scans >= 60:
            return "high"    # 60+ engines
        elif total_scans >= 40:
            return "medium"  # 40-59 engines
        else:
            return "low"     # <40 engines
    
    def _get_component_explanation(self, component: str, score: float, data: Dict) -> str:
        """Generate human-readable explanation for component score"""
        
        max_score = self.WEIGHTS[component]
        percentage = (score / max_score * 100) if max_score > 0 else 0
        
        if component == "detection_ratio":
            return self._explain_detection_ratio(score, data.get('detection_stats', {}), data.get('detection_ratio', '0/0'))
        elif component == "signature_verification":
            return self._explain_signature(score, data.get('signature', {}))
        elif component == "file_reputation":
            return self._explain_file_reputation(score, data)
        elif component == "threat_classification":
            return self._explain_threat_classification(score, data.get('threat_classification', {}), data.get('tags', []))
        elif component == "vendor_trust":
            return self._explain_vendor_trust(score, data.get('vendor'), data.get('signature', {}))
        
        return f"Scored {score:.1f}/{max_score} points ({percentage:.0f}%)"
    
    def _explain_detection_ratio(self, score: float, detection_stats: Dict, ratio: str) -> str:
        """Explain detection ratio score using actual API data"""
        
        malicious = detection_stats.get('malicious', 0)
        suspicious = detection_stats.get('suspicious', 0)
        undetected = detection_stats.get('undetected', 0)
        harmless = detection_stats.get('harmless', 0)
        total = sum(detection_stats.values())
        
        if total == 0:
            return f"No scan data available - scored {score:.1f}/40 points"
        
        clean = undetected + harmless
        
        if malicious > 0:
            return f"⚠️ {malicious} malicious + {suspicious} suspicious out of {total} engines - scored {score:.1f}/40 points"
        elif suspicious > 0:
            return f"⚠️ {suspicious} suspicious detections out of {total} engines - scored {score:.1f}/40 points"
        else:
            return f"✓ Clean - {clean}/{total} engines found no threats - scored {score:.1f}/40 points"
    
    def _explain_signature(self, score: float, signature: Dict) -> str:
        """Explain signature score using API data"""
        
        if not signature:
            return f"No digital signature data - scored {score:.1f}/20 points"
        
        verified = signature.get('verified', 'Unknown')
        
        if 'valid' in str(verified).lower() and 'invalid' not in str(verified).lower():
            return f"✓ Valid digital signature verified - scored {score:.1f}/20 points"
        elif 'invalid' in str(verified).lower():
            return f"❌ Invalid signature detected - scored {score:.1f}/20 points"
        else:
            return f"Signature present, verification status: {verified} - scored {score:.1f}/20 points"
    
    def _explain_file_reputation(self, score: float, data: Dict) -> str:
        """Explain file reputation score using API data"""
        
        last_analysis = data.get('last_analysis_date')
        
        if last_analysis:
            try:
                analysis_date = datetime.fromisoformat(last_analysis.replace('Z', '+00:00'))
                days_old = (datetime.now(analysis_date.tzinfo) - analysis_date).days
                
                if days_old < 30:
                    return f"File analyzed {days_old} days ago (recent) - scored {score:.1f}/15 points"
                else:
                    return f"File analyzed {days_old} days ago - scored {score:.1f}/15 points"
            except:
                pass
        
        return f"File analysis history available - scored {score:.1f}/15 points"
    
    def _explain_threat_classification(self, score: float, threat_class: Dict, tags: List[str]) -> str:
        """Explain threat classification score using API data"""
        
        if not threat_class:
            return f"No threat classification data from VirusTotal - scored {score:.1f}/15 points"
        
        threat_label = threat_class.get('suggested_threat_label', '')
        
        if threat_label and threat_label.strip() and threat_label.lower() not in ['none', 'clean', 'unknown']:
            return f"⚠️ VirusTotal classified as: {threat_label} - scored {score:.1f}/15 points"
        else:
            return f"✓ No threat classification from VirusTotal - scored {score:.1f}/15 points"
    
    def _explain_vendor_trust(self, score: float, vendor: str, signature: Dict) -> str:
        """Explain vendor trust score using API signature data"""
        
        if not signature:
            return f"No signature verification data - scored {score:.1f}/10 points"
        
        verified = signature.get('verified', 'Unknown')
        
        if 'valid' in str(verified).lower() and 'invalid' not in str(verified).lower():
            return f"✓ Valid signature verified - scored {score:.1f}/10 points"
        elif 'invalid' in str(verified).lower():
            return f"❌ Invalid signature - scored {score:.1f}/10 points"
        else:
            return f"Signature status: {verified} - scored {score:.1f}/10 points"
