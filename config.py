import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    # API Keys
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
    PRODUCTHUNT_API_KEY = os.getenv('PRODUCTHUNT_API_KEY')
    NVD_API_KEY = os.getenv('NVD_API_KEY')  # Optional: Increases rate limits from 5 to 50 requests per 30 seconds
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')  # Required for SHA1 hash lookups
    
    # Deprecated - replaced by NVD API
    # OPENCVE_USERNAME = os.getenv('OPENCVE_USERNAME')
    # OPENCVE_PASSWORD = os.getenv('OPENCVE_PASSWORD')
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    FLASK_ENV = os.getenv('FLASK_ENV', 'development')
    DEBUG = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    
    # Database
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'data/assessments.db')
    
    # API Endpoints
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    PRODUCTHUNT_API_BASE = "https://api.producthunt.com/v2/api/graphql"
    
    # LLM Settings
    GEMINI_MODEL = "gemini-2.0-flash"
    GEMINI_TEMPERATURE = 0.1  # Low temperature for consistent, factual responses
    GEMINI_MAX_TOKENS = 4096
    
    # Multi-Agent Settings
    USE_MULTI_AGENT = os.getenv('USE_MULTI_AGENT', 'True').lower() == 'true'  # Enable multi-agent verification by default
    
    # Cache settings
    CACHE_EXPIRY_HOURS = 24
