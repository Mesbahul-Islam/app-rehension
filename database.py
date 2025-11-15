"""
Database and caching layer for assessment storage using SQLAlchemy ORM
"""
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import os

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Index, CheckConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

logger = logging.getLogger(__name__)

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


logger = logging.getLogger(__name__)


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
        
        logger.info(f"Database initialized with SQLAlchemy ORM: {self.db_path}")
    
    def _get_session(self) -> Session:
        """Get a new database session"""
        return self.SessionLocal()
    
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
            logger.error(f"Error saving assessment: {e}")
            raise
        finally:
            session.close()
    
    def get_assessment(self, product_name: Optional[str] = None, vendor: Optional[str] = None, 
                      max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """Retrieve a cached assessment if it's fresh enough (by product or vendor) using ORM"""
        
        if not product_name and not vendor:
            return None
        
        session = self._get_session()
        try:
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            if product_name:
                assessment = session.query(Assessment).filter(
                    Assessment.product_name == product_name,
                    Assessment.updated_at > cutoff_time
                ).order_by(Assessment.updated_at.desc()).first()
            else:
                assessment = session.query(Assessment).filter(
                    Assessment.vendor == vendor,
                    Assessment.product_name.is_(None),
                    Assessment.updated_at > cutoff_time
                ).order_by(Assessment.updated_at.desc()).first()
            
            if assessment:
                result = json.loads(assessment.assessment_data)
                result['_cached'] = True
                result['_cache_timestamp'] = assessment.updated_at.isoformat()
                return result
            
            return None
            
        finally:
            session.close()
    
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
            logger.error(f"Error saving raw data: {e}")
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
            
            logger.info(f"Cleaned up {deleted} expired cache entries")
            return deleted
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error cleaning up expired cache: {e}")
            raise
        finally:
            session.close()
