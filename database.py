"""Lightweight JSON-based caching for assessments and API responses."""

import json
import logging
import os
import threading
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_EMPTY_CACHE: Dict[str, Any] = {
    "assessments": [],
    "raw_data": {}
}


class AssessmentCache:
    """Simple JSON file cache used across the app."""

    def __init__(self, cache_path: str, default_expiry_hours: int = 24):
        # Always use absolute path to avoid issues with working directory changes
        self.cache_path = os.path.abspath(cache_path)
        self.default_expiry_hours = default_expiry_hours
        self._lock = threading.Lock()
        logger.info(f"[CACHE] Initialized with path: {self.cache_path}")
        self._ensure_cache_file()

    def _ensure_cache_file(self) -> None:
        cache_dir = os.path.dirname(self.cache_path)
        if cache_dir and not os.path.exists(cache_dir):
            os.makedirs(cache_dir, exist_ok=True)

        if not os.path.exists(self.cache_path):
            with open(self.cache_path, "w", encoding="utf-8") as cache_file:
                json.dump(_EMPTY_CACHE, cache_file, indent=2)

    def _load_cache(self) -> Dict[str, Any]:
        try:
            with open(self.cache_path, "r", encoding="utf-8") as cache_file:
                data = json.load(cache_file)
        except FileNotFoundError:
            data = deepcopy(_EMPTY_CACHE)
        except json.JSONDecodeError:
            logger.warning("Cache file corrupted. Re-initializing JSON cache.")
            data = deepcopy(_EMPTY_CACHE)

        # Ensure required keys exist
        data.setdefault("assessments", [])
        data.setdefault("raw_data", {})
        return data

    def _save_cache(self, data: Dict[str, Any]) -> None:
        with open(self.cache_path, "w", encoding="utf-8") as cache_file:
            json.dump(data, cache_file, indent=2)

    @staticmethod
    def _normalize(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    def _deepcopy(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return deepcopy(payload)

    def _hydrate_result(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        payload = self._deepcopy(entry.get("result", {}))
        payload.setdefault("_cached", True)
        payload.setdefault("_cache_timestamp", entry.get("updated_at"))
        payload.setdefault("_cache_source", "assessment-cache")
        payload.setdefault("_cache_query", entry.get("query"))
        return payload

    def _find_entry(self, entries: List[Dict[str, Any]], *,
                    query: Optional[str] = None,
                    product_name: Optional[str] = None,
                    vendor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        for entry in entries:
            if query and entry.get("query") == query:
                return entry
            if product_name and entry.get("product_name_norm") == product_name:
                return entry
            if not product_name and vendor and entry.get("vendor_norm") == vendor and not entry.get("product_name_norm"):
                return entry
        return None

    def _next_id(self, entries: List[Dict[str, Any]]) -> int:
        if not entries:
            return 1
        return max(entry.get("id", 0) for entry in entries) + 1

    def get_assessment_by_query(self, search_term: str, max_age_hours: Optional[int] = None) -> Optional[Dict[str, Any]]:
        if not search_term:
            return None

        normalized_query = self._normalize(search_term)
        if not normalized_query:
            return None

        logger.info(f"[CACHE] Lookup: '{search_term}' (normalized: '{normalized_query}')")
        
        data = self._load_cache()
        logger.info(f"[CACHE] Loaded {len(data['assessments'])} entries from cache file")
        
        cutoff = datetime.now() - timedelta(hours=max_age_hours or self.default_expiry_hours)

        for idx, entry in enumerate(data["assessments"]):
            entry_query = entry.get("query")
            logger.info(f"[CACHE]   Entry {idx}: query='{entry_query}', product='{entry.get('product_name_norm')}', vendor='{entry.get('vendor_norm')}'")
            
            if not self._query_matches_entry(normalized_query, entry):
                continue

            logger.info(f"[CACHE]   ✓ Match found for '{normalized_query}' in entry {idx}")
            
            updated_at = self._parse_timestamp(entry.get("updated_at"))
            if not updated_at or updated_at < cutoff:
                logger.info(f"[CACHE]   ✗ Entry expired (updated: {updated_at}, cutoff: {cutoff})")
                continue

            logger.info(f"[CACHE]   ✓ HIT for '{search_term}' - returning cached result")
            return self._hydrate_result(entry)

        logger.info(f"[CACHE]   ✗ MISS for '{search_term}' - no valid entry found")
        return None

    @staticmethod
    def _query_matches_entry(normalized_query: str, entry: Dict[str, Any]) -> bool:
        if entry.get("query") == normalized_query:
            return True

        for field in ("product_name_norm", "vendor_norm"):
            value = entry.get(field)
            if not value:
                continue
            if value == normalized_query:
                return True

            # Basic fuzzy match: allow substring matches in either direction
            if normalized_query in value or value in normalized_query:
                return True

        return False

    def get_assessment(self, product_name: Optional[str] = None, vendor: Optional[str] = None,
                       max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        if not product_name and not vendor:
            return None

        normalized_product = self._normalize(product_name)
        normalized_vendor = self._normalize(vendor)
        data = self._load_cache()
        cutoff = datetime.now() - timedelta(hours=max_age_hours)

        for entry in data["assessments"]:
            if normalized_product and entry.get("product_name_norm") != normalized_product:
                continue
            if not normalized_product and normalized_vendor and entry.get("vendor_norm") != normalized_vendor:
                continue

            updated_at = self._parse_timestamp(entry.get("updated_at"))
            if not updated_at or updated_at < cutoff:
                continue

            return self._hydrate_result(entry)

        return None

    def save_assessment(self, product_name: Optional[str], assessment_data: Dict[str, Any],
                        vendor: Optional[str] = None, url: Optional[str] = None,
                        search_term: Optional[str] = None) -> int:
        if not any([product_name, vendor, search_term]):
            raise ValueError("At least one identifier is required to store an assessment")

        normalized_query = self._normalize(search_term)
        normalized_product = self._normalize(product_name)
        normalized_vendor = self._normalize(vendor)
        now = datetime.now().isoformat()

        logger.info(f"[CACHE] Saving: query='{search_term}' (norm: '{normalized_query}'), product='{product_name}', vendor='{vendor}'")

        with self._lock:
            data = self._load_cache()
            entries = data["assessments"]
            entry = self._find_entry(entries, query=normalized_query,
                                     product_name=normalized_product, vendor=normalized_vendor)

            if entry is None:
                logger.info(f"[CACHE]   Creating new entry (ID: {self._next_id(entries)})")
                entry = {
                    "id": self._next_id(entries),
                    "created_at": now
                }
                entries.append(entry)

            else:
                logger.info(f"[CACHE]   Updating existing entry (ID: {entry.get('id')})")
            
            entry.update({
                "query": normalized_query,
                "product_name": product_name,
                "vendor": vendor,
                "url": url,
                "product_name_norm": normalized_product,
                "vendor_norm": normalized_vendor,
                "result": self._deepcopy(assessment_data),
                "trust_score": self._extract_trust_score(assessment_data),
                "updated_at": now
            })

            self._save_cache(data)
            logger.info(f"[CACHE]   ✓ Saved successfully (ID: {entry['id']}, total: {len(entries)} entries)")
            return entry["id"]

    @staticmethod
    def _extract_trust_score(assessment_data: Dict[str, Any]) -> Optional[int]:
        trust = assessment_data.get("trust_score", {}) if isinstance(assessment_data, dict) else {}
        if isinstance(trust, dict):
            for key in ("score", "total_score"):
                value = trust.get(key)
                if isinstance(value, (int, float)):
                    return int(value)
        return None

    def get_all_assessments(self, limit: int = 100) -> List[Dict[str, Any]]:
        data = self._load_cache()
        entries = data["assessments"]
        sorted_entries = sorted(
            entries,
            key=lambda item: self._parse_timestamp(item.get("updated_at")) or datetime.min,
            reverse=True
        )

        result = []
        for entry in sorted_entries[:limit]:
            result.append({
                "id": entry.get("id"),
                "product_name": entry.get("product_name"),
                "vendor": entry.get("vendor"),
                "trust_score": entry.get("trust_score"),
                "created_at": entry.get("created_at"),
                "updated_at": entry.get("updated_at")
            })

        return result

    def get_assessment_by_id(self, assessment_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a specific cached assessment by its ID"""
        logger.info(f"[CACHE] Looking up assessment by ID: {assessment_id}")
        data = self._load_cache()
        entries = data["assessments"]
        
        for entry in entries:
            if entry.get("id") == assessment_id:
                logger.info(f"[CACHE] ✓ Found assessment ID {assessment_id}")
                return self._hydrate_result(entry)
        
        logger.info(f"[CACHE] ✗ Assessment ID {assessment_id} not found")
        return None

    def save_raw_data(self, cache_key: str, data_type: str, data: Any,
                      expiry_hours: Optional[int] = None) -> None:
        if not cache_key:
            return

        expires_at = datetime.now() + timedelta(hours=expiry_hours or self.default_expiry_hours)
        with self._lock:
            payload = self._load_cache()
            payload["raw_data"][cache_key] = {
                "data_type": data_type,
                "data": data,
                "created_at": datetime.now().isoformat(),
                "expires_at": expires_at.isoformat()
            }
            self._save_cache(payload)

    def get_raw_data(self, cache_key: str) -> Optional[Any]:
        if not cache_key:
            return None

        payload = self._load_cache()
        entry = payload["raw_data"].get(cache_key)
        if not entry:
            return None

        expires_at = self._parse_timestamp(entry.get("expires_at"))
        if not expires_at or expires_at < datetime.now():
            with self._lock:
                payload = self._load_cache()
                payload["raw_data"].pop(cache_key, None)
                self._save_cache(payload)
            return None

        return entry.get("data")

    def cleanup_expired(self) -> int:
        payload = self._load_cache()
        now = datetime.now()
        removed = []
        for key, entry in list(payload["raw_data"].items()):
            expires_at = self._parse_timestamp(entry.get("expires_at"))
            if not expires_at or expires_at < now:
                removed.append(key)
                payload["raw_data"].pop(key, None)

        if removed:
            with self._lock:
                self._save_cache(payload)

        return len(removed)
