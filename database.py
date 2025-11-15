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
    
    def _migrate_schema_if_needed(self):
        """Migrate old schema to support vendor-only assessments"""
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

                    # SQLite doesn't support ALTER TABLE to modify constraints
                    # We need to recreate the table
                    
                    # 1. Rename old table
                    cursor.execute("ALTER TABLE assessments RENAME TO assessments_old")
                    
                    # 2. Create new table with updated schema
                    cursor.execute("""
                        CREATE TABLE assessments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            product_name TEXT,
                            vendor TEXT,
                            url TEXT,
                            assessment_data TEXT NOT NULL,
                            trust_score INTEGER,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            CONSTRAINT check_product_or_vendor CHECK (product_name IS NOT NULL OR vendor IS NOT NULL)
                        )
                    """)
                    
                    # 3. Copy data from old table
                    cursor.execute("""
                        INSERT INTO assessments (id, product_name, vendor, url, assessment_data, 
                                                trust_score, created_at, updated_at)
                        SELECT id, product_name, vendor, url, assessment_data, 
                               trust_score, created_at, updated_at
                        FROM assessments_old
                    """)
                    
                    # 4. Drop old table
                    cursor.execute("DROP TABLE assessments_old")
                    
                    # 5. Recreate indexes
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_product_name 
                        ON assessments(product_name)
                    """)
                    
                    cursor.execute("""
                        CREATE INDEX IF NOT EXISTS idx_vendor 
                        ON assessments(vendor)
                    """)
                    
                    conn.commit()

        except Exception as e:
            logger.error(f"Error during schema migration: {e}")
            # Don't fail initialization if migration fails
    
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
            
            cursor.execute("""
                DELETE FROM data_cache
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
            
            deleted = cursor.rowcount
            conn.commit()

            return deleted
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error cleaning up expired cache: {e}")
            raise
        finally:
            session.close()
