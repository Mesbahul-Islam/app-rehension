"""
Database and caching layer for assessment storage
"""
import sqlite3
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import os

logger = logging.getLogger(__name__)


class AssessmentCache:
    """SQLite-based cache for assessment results"""
    
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
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Assessments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assessments (
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
            
            # Create index for faster lookups
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_product_name 
                ON assessments(product_name)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vendor 
                ON assessments(vendor)
            """)
            
            # Raw data cache table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS data_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cache_key TEXT UNIQUE NOT NULL,
                    data_type TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL
                )
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_key 
                ON data_cache(cache_key)
            """)
            
            conn.commit()
            
        # Run migration if needed
        self._migrate_schema_if_needed()
    
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
                    logger.info("Migrating database schema to support vendor-only assessments...")
                    
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
                    logger.info("Database schema migration completed successfully")
                    
        except Exception as e:
            logger.error(f"Error during schema migration: {e}")
            # Don't fail initialization if migration fails
    
    def save_assessment(self, product_name: Optional[str], assessment_data: Dict[str, Any], 
                       vendor: Optional[str] = None, url: Optional[str] = None) -> int:
        """Save or update an assessment (product or vendor)"""
        
        # Ensure at least one identifier is provided
        if not product_name and not vendor:
            raise ValueError("Either product_name or vendor must be provided")
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Check if assessment exists (by product_name or vendor)
            if product_name:
                cursor.execute(
                    "SELECT id FROM assessments WHERE product_name = ?",
                    (product_name,)
                )
            else:
                cursor.execute(
                    "SELECT id FROM assessments WHERE vendor = ? AND product_name IS NULL",
                    (vendor,)
                )
            existing = cursor.fetchone()
            
            trust_score = assessment_data.get('trust_score', {}).get('total_score')
            data_json = json.dumps(assessment_data, indent=2)
            
            if existing:
                # Update existing
                cursor.execute("""
                    UPDATE assessments 
                    SET assessment_data = ?, 
                        vendor = ?,
                        url = ?,
                        trust_score = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (data_json, vendor, url, trust_score, existing[0]))
                assessment_id = existing[0]
            else:
                # Insert new
                cursor.execute("""
                    INSERT INTO assessments (product_name, vendor, url, assessment_data, trust_score)
                    VALUES (?, ?, ?, ?, ?)
                """, (product_name, vendor, url, data_json, trust_score))
                assessment_id = cursor.lastrowid
            
            conn.commit()
            return assessment_id
    
    def get_assessment(self, product_name: Optional[str] = None, vendor: Optional[str] = None, 
                      max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        """Retrieve a cached assessment if it's fresh enough (by product or vendor)"""
        
        if not product_name and not vendor:
            return None
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
            
            if product_name:
                cursor.execute("""
                    SELECT assessment_data, created_at, updated_at
                    FROM assessments
                    WHERE product_name = ?
                    AND updated_at > ?
                    ORDER BY updated_at DESC
                    LIMIT 1
                """, (product_name, cutoff_time))
            else:
                cursor.execute("""
                    SELECT assessment_data, created_at, updated_at
                    FROM assessments
                    WHERE vendor = ? AND product_name IS NULL
                    AND updated_at > ?
                    ORDER BY updated_at DESC
                    LIMIT 1
                """, (vendor, cutoff_time))
            
            row = cursor.fetchone()
            
            if row:
                assessment = json.loads(row['assessment_data'])
                assessment['_cached'] = True
                assessment['_cache_timestamp'] = row['updated_at']
                return assessment
            
            return None
    
    def get_all_assessments(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all assessments"""
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, product_name, vendor, trust_score, created_at, updated_at
                FROM assessments
                ORDER BY updated_at DESC
                LIMIT ?
            """, (limit,))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'id': row['id'],
                    'product_name': row['product_name'],
                    'vendor': row['vendor'],
                    'trust_score': row['trust_score'],
                    'created_at': row['created_at'],
                    'updated_at': row['updated_at']
                })
            
            return results
    
    def save_raw_data(self, cache_key: str, data_type: str, data: Any, 
                     expiry_hours: int = 24) -> None:
        """Cache raw API data"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            expires_at = datetime.now() + timedelta(hours=expiry_hours)
            data_json = json.dumps(data)
            
            cursor.execute("""
                INSERT OR REPLACE INTO data_cache (cache_key, data_type, data, expires_at)
                VALUES (?, ?, ?, ?)
            """, (cache_key, data_type, data_json, expires_at))
            
            conn.commit()
    
    def get_raw_data(self, cache_key: str) -> Optional[Any]:
        """Retrieve cached raw data if not expired"""
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT data, expires_at
                FROM data_cache
                WHERE cache_key = ?
                AND expires_at > CURRENT_TIMESTAMP
            """, (cache_key,))
            
            row = cursor.fetchone()
            
            if row:
                return json.loads(row['data'])
            
            return None
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE FROM data_cache
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
            
            deleted = cursor.rowcount
            conn.commit()
            
            logger.info(f"Cleaned up {deleted} expired cache entries")
            return deleted
