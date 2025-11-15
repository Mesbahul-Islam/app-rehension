"""Lightweight JSON-based caching for assessments and API responses."""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import os
import threading
from copy import deepcopy
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# Create declarative base
Base = declarative_base()


class Assessment(Base):
    """ORM model for assessment cache"""
    __tablename__ = 'assessments'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    product_name = Column(String, nullable=True, index=True)
    vendor = Column(String, nullable=True, index=True)
    url = Column(String, nullable=True)
    assessment_data = Column(Text, nullable=False)
    trust_score = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    
    __table_args__ = (
        CheckConstraint('product_name IS NOT NULL OR vendor IS NOT NULL', name='check_product_or_vendor'),
        Index('idx_product_name', 'product_name'),
        Index('idx_vendor', 'vendor'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to dictionary"""
        return {
            'id': self.id,
            'product_name': self.product_name,
            'vendor': self.vendor,
            'trust_score': self.trust_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class DataCache(Base):
    """ORM model for raw data cache"""
    __tablename__ = 'data_cache'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    cache_key = Column(String, unique=True, nullable=False, index=True)
    data_type = Column(String, nullable=False)
    data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    
    __table_args__ = (
        Index('idx_cache_key', 'cache_key'),
    )


class AssessmentCache:
    """SQLAlchemy ORM-based cache for assessment results"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._ensure_db_directory()
        self._init_db()
    
    def _ensure_db_directory(self):
        """Create database directory if it doesn't exist"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir)
    
    def _init_db(self):
        """Initialize database using SQLAlchemy ORM"""
        # Create SQLite engine
        db_url = f'sqlite:///{self.db_path}'
        self.engine = create_engine(
            db_url,
            connect_args={'check_same_thread': False},
            poolclass=StaticPool,
            echo=False  # Set to True for SQL debugging
        )
        
        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
        # Create all tables
        Base.metadata.create_all(bind=self.engine)
    
    def _get_session(self) -> Session:
        """Create and return a new database session"""
        return self.SessionLocal()
    
    def _migrate_schema_if_needed(self):
        """Migrate old schema to support vendor-only assessments"""
        import sqlite3
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if old schema exists (product_name with NOT NULL constraint)
                cursor.execute("PRAGMA table_info(assessments)")
                columns = cursor.fetchall()
                
                # Look for product_name column
                product_name_col = None
                for col in columns:
                    if col[1] == 'product_name':
                        product_name_col = col
                        break
                
                # If product_name exists and has NOT NULL constraint (col[3] == 1)
                if product_name_col and product_name_col[3] == 1:

                    def __init__(self, cache_path: str, default_expiry_hours: int = 24):
                    # Always use absolute path to avoid issues with working directory changes
                        self.cache_path = os.path.abspath(cache_path)
                        self.default_expiry_hours = default_expiry_hours
                        self._lock = threading.Lock()
                        logger.info(f"[CACHE] Initialized with path: {self.cache_path}")
                        self._ensure_cache_file()

        except Exception as e:
            pass
    
    def save_assessment(self, product_name: Optional[str], assessment_data: Dict[str, Any], 
                       vendor: Optional[str] = None, url: Optional[str] = None) -> int:
        """Save or update an assessment (product or vendor) using ORM"""
        
        # Ensure at least one identifier is provided
        if not product_name and not vendor:
            raise ValueError("Either product_name or vendor must be provided")
        
        session = self._get_session()
        try:
            # Check if assessment exists (by product_name or vendor)
            if product_name:
                existing = session.query(Assessment).filter(
                    Assessment.product_name == product_name
                ).first()
            else:
                existing = session.query(Assessment).filter(
                    Assessment.vendor == vendor,
                    Assessment.product_name.is_(None)
                ).first()
            
            trust_score = assessment_data.get('trust_score', {}).get('total_score')
            data_json = json.dumps(assessment_data, indent=2)
            
            if existing:
                # Update existing
                existing.assessment_data = data_json
                existing.vendor = vendor
                existing.url = url
                existing.trust_score = trust_score
                existing.updated_at = datetime.now()
                assessment_id = existing.id
            else:
                # Insert new
                new_assessment = Assessment(
                    product_name=product_name,
                    vendor=vendor,
                    url=url,
                    assessment_data=data_json,
                    trust_score=trust_score
                )
                session.add(new_assessment)
                session.flush()
                assessment_id = new_assessment.id
            
            session.commit()
            return assessment_id
            
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
    
    def get_assessment(self, product_name: Optional[str] = None, vendor: Optional[str] = None, 
                      max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """Retrieve a cached assessment if it's fresh enough (by product or vendor) using ORM"""
        
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
        """Get all assessments using ORM"""
        
        session = self._get_session()
        try:
            assessments = session.query(Assessment).order_by(
                Assessment.updated_at.desc()
            ).limit(limit).all()
            
            return [assessment.to_dict() for assessment in assessments]
            
        finally:
            session.close()
    
    def save_raw_data(self, cache_key: str, data_type: str, data: Any, 
                     expiry_hours: int = 24) -> None:
        """Cache raw API data using ORM"""
        
        session = self._get_session()
        try:
            expires_at = datetime.now() + timedelta(hours=expiry_hours)
            data_json = json.dumps(data)
            
            # Check if cache entry exists
            existing = session.query(DataCache).filter(
                DataCache.cache_key == cache_key
            ).first()
            
            if existing:
                # Update existing
                existing.data_type = data_type
                existing.data = data_json
                existing.expires_at = expires_at
                existing.created_at = datetime.now()
            else:
                # Insert new
                new_cache = DataCache(
                    cache_key=cache_key,
                    data_type=data_type,
                    data=data_json,
                    expires_at=expires_at
                )
                session.add(new_cache)
            
            session.commit()
            
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
    
    def get_raw_data(self, cache_key: str) -> Optional[Any]:
        """Retrieve cached raw data if not expired using ORM"""
        
        session = self._get_session()
        try:
            cache_entry = session.query(DataCache).filter(
                DataCache.cache_key == cache_key,
                DataCache.expires_at > datetime.now()
            ).first()
            
            if cache_entry:
                return json.loads(cache_entry.data)
            
            return None
            
        finally:
            session.close()
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries using ORM"""
        
        session = self._get_session()
        try:
            deleted = session.query(DataCache).filter(
                DataCache.expires_at < datetime.now()
            ).delete()
            
            session.commit()
            return deleted
            
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()
