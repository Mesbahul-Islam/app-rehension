"""
Evidence registry for tracking and citing all data sources used in assessments.
Distinguishes vendor-stated claims from independent verification.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import hashlib
import json


@dataclass
class EvidenceItem:
    """Single piece of evidence with source attribution."""
    id: str
    source_name: str  # e.g., "OpenCVE", "ProductHunt", "Vendor Trust Page"
    source_type: str  # "vendor" | "independent" | "mixed"
    claim_text: str
    url: Optional[str]
    timestamp: str
    confidence: str  # "high" | "medium" | "low"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "source_name": self.source_name,
            "source_type": self.source_type,
            "claim_text": self.claim_text,
            "url": self.url,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


class EvidenceRegistry:
    """Aggregates and manages all evidence for an assessment."""
    
    def __init__(self):
        self.items: List[EvidenceItem] = []
        self._id_counter = 0
    
    def _generate_id(self) -> str:
        """Generate unique evidence ID."""
        self._id_counter += 1
        return f"ev_{self._id_counter:04d}"
    
    def add_vendor_claim(
        self,
        source_name: str,
        claim_text: str,
        url: Optional[str] = None,
        confidence: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add a vendor-stated claim."""
        evidence_id = self._generate_id()
        item = EvidenceItem(
            id=evidence_id,
            source_name=source_name,
            source_type="vendor",
            claim_text=claim_text,
            url=url,
            timestamp=datetime.now().isoformat(),
            confidence=confidence,
            metadata=metadata or {}
        )
        self.items.append(item)
        return evidence_id
    
    def add_independent_claim(
        self,
        source_name: str,
        claim_text: str,
        url: Optional[str] = None,
        confidence: str = "high",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add an independently verified claim."""
        evidence_id = self._generate_id()
        item = EvidenceItem(
            id=evidence_id,
            source_name=source_name,
            source_type="independent",
            claim_text=claim_text,
            url=url,
            timestamp=datetime.now().isoformat(),
            confidence=confidence,
            metadata=metadata or {}
        )
        self.items.append(item)
        return evidence_id
    
    def add_mixed_claim(
        self,
        source_name: str,
        claim_text: str,
        url: Optional[str] = None,
        confidence: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add a claim that combines vendor and independent sources."""
        evidence_id = self._generate_id()
        item = EvidenceItem(
            id=evidence_id,
            source_name=source_name,
            source_type="mixed",
            claim_text=claim_text,
            url=url,
            timestamp=datetime.now().isoformat(),
            confidence=confidence,
            metadata=metadata or {}
        )
        self.items.append(item)
        return evidence_id
    
    def get_by_id(self, evidence_id: str) -> Optional[EvidenceItem]:
        """Retrieve evidence by ID."""
        for item in self.items:
            if item.id == evidence_id:
                return item
        return None
    
    def get_by_source_type(self, source_type: str) -> List[EvidenceItem]:
        """Get all evidence of a specific type."""
        return [item for item in self.items if item.source_type == source_type]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics about evidence."""
        total = len(self.items)
        vendor_count = len([i for i in self.items if i.source_type == "vendor"])
        independent_count = len([i for i in self.items if i.source_type == "independent"])
        mixed_count = len([i for i in self.items if i.source_type == "mixed"])
        
        return {
            "total_evidence": total,
            "vendor_stated": vendor_count,
            "independent_verification": independent_count,
            "mixed_sources": mixed_count,
            "vendor_percentage": round(vendor_count / total * 100, 1) if total > 0 else 0,
            "independent_percentage": round(independent_count / total * 100, 1) if total > 0 else 0,
            "evidence_quality": self._calculate_quality_score()
        }
    
    def _calculate_quality_score(self) -> str:
        """Calculate overall evidence quality."""
        if not self.items:
            return "insufficient"
        
        independent_count = len([i for i in self.items if i.source_type == "independent"])
        total = len(self.items)
        independent_ratio = independent_count / total if total > 0 else 0
        
        if total < 3:
            return "insufficient"
        elif independent_ratio >= 0.5:
            return "high"
        elif independent_ratio >= 0.25:
            return "medium"
        else:
            return "low"
    
    def has_sufficient_evidence(self, min_items: int = 3) -> bool:
        """Check if sufficient evidence exists for analysis."""
        return len(self.items) >= min_items
    
    def get_evidence_hash(self) -> str:
        """Generate SHA256 hash of all evidence for reproducibility."""
        evidence_data = json.dumps(
            [item.to_dict() for item in self.items],
            sort_keys=True
        )
        return hashlib.sha256(evidence_data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Export all evidence to dictionary."""
        return {
            "items": [item.to_dict() for item in self.items],
            "summary": self.get_summary(),
            "evidence_hash": self.get_evidence_hash()
        }
    
    def get_citations_list(self) -> List[Dict[str, Any]]:
        """Get formatted citations list for assessment output."""
        return [
            {
                "id": item.id,
                "source": item.source_name,
                "source_type": item.source_type,
                "content": item.claim_text,
                "url": item.url,
                "confidence": item.confidence,
                "timestamp": item.timestamp
            }
            for item in self.items
        ]
