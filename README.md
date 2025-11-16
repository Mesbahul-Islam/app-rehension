# 🛡️ Security Assessor

An AI-powered security assessment tool that transforms a product name or URL into a CISO-ready trust brief with sources in minutes.

## Overview

Security teams and CISOs are constantly asked to approve new tools they've never seen before. This tool provides accurate, concise, and source-grounded snapshots of a product's security posture using:

- **LLM Analysis**: Google Gemini for intelligent synthesis and analysis
- **RAG Architecture**: Retrieval-Augmented Generation for fact-based assessments
- **Multiple Data Sources**: ProductHunt, OpenCVE, CISA KEV catalog
- **Web UI**: Flask-based interface with comparison features
- **Local Cache**: JSON file for reproducibility and faster results

## Features

✅ **Entity Resolution**: Automatically identifies product name, vendor, and URLs  
✅ **Classification**: Categorizes software into clear taxonomy (SaaS, GenAI tool, Developer tool, etc.)  
✅ **Vulnerability Analysis**: Fetches and analyzes CVE data and Known Exploited Vulnerabilities (KEV)  
✅ **Trust Score**: 0-100 score with detailed rationale and confidence level  
✅ **Risk Assessment**: Comprehensive security posture with evidence-based findings  
✅ **Alternative Suggestions**: Recommends 1-2 safer alternatives  
✅ **Comparison View**: Side-by-side comparison of multiple products  
✅ **Cached Results**: Local JSON cache for reproducibility and timestamp tracking  
✅ **Source Citations**: All findings linked to authoritative sources  

## Architecture

```
User Input → Entity Resolution (Gemini) → Data Gathering (APIs) → 
Analysis (Gemini) → Trust Score Calculation → Assessment Report
          ↓
        JSON Cache (Reproducibility)
```

### Components

- **Flask Web UI**: Modern, responsive interface
- **Gemini LLM**: Entity resolution, classification, vulnerability analysis, scoring
- **Data Sources**:
  - ProductHunt API: Product information and metadata
  - OpenCVE API: CVE vulnerability data
  - CISA KEV: Known Exploited Vulnerabilities catalog
- **JSON Cache File**: Cached assessments and raw API data
- **Assessment Engine**: Orchestrates workflow and compiles reports

## Installation

### Prerequisites

- Python 3.8+
- Google Gemini API key
- ProductHunt API key (optional, for enhanced product data)

### Setup

1. **Clone or navigate to the project directory**:
```bash
cd /home/mesbahul/Documents/hackathon_project
```

2. **Create a virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**:
```bash
cp .env.example .env
nano .env  # Edit with your API keys
```

Add your API keys to `.env`:
```env
GEMINI_API_KEY=your_gemini_api_key_here
PRODUCTHUNT_API_KEY=your_producthunt_api_key_here  # Optional
```

### Getting API Keys

#### Google Gemini API Key (Required)
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the key to your `.env` file

#### ProductHunt API Key (Optional)
1. Visit [ProductHunt API](https://api.producthunt.com/v2/docs)
2. Create an account and register an application
3. Get your access token
4. Add to `.env` file

## Usage

### Running the Web Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

### Web Interface Features

1. **Home Page**: Enter product name, vendor, or URL for assessment
2. **History**: View all previously generated assessments
3. **Compare**: Side-by-side comparison of multiple products

### API Endpoints

- `POST /assess`: Generate security assessment
- `GET /history`: View assessment history
- `GET /compare`: Compare products interface
- `GET /api/health`: Health check

### Example Assessment Request

```bash
curl -X POST http://localhost:5000/assess \
  -H "Content-Type: application/json" \
  -d '{
    "input_text": "Slack",
    "use_cache": true
  }'
```

## Assessment Output

Each assessment includes:

### 1. Entity Information
- Product name
- Vendor/company
- Primary website URL
- Aliases and alternative names
- Confidence level

### 2. Classification
- Primary category (e.g., SaaS Application, GenAI Tool, Developer Tool)
- Sub-category (specific type)
- Use cases
- Deployment model

### 3. Security Posture
- **Vulnerability Summary**:
  - Total CVEs found
  - Known Exploited Vulnerabilities (KEV)
  - Vulnerability trend (improving/stable/concerning)
  - Exploitation risk (high/medium/low)
  - Severity distribution
- **Critical Findings**: Immediate attention items
- **Key Concerns**: Security issues identified
- **Recent CVEs**: Latest vulnerabilities (top 5)
- **KEV List**: Known exploited vulnerabilities

### 4. Trust Score (0-100)
- Overall score with color coding
- Risk level (critical/high/medium/low)
- Confidence (high/medium/low)
- Detailed rationale
- Scoring breakdown:
  - Vulnerability history (30%)
  - KEV presence (25%)
  - Vendor reputation (20%)
  - Product maturity (15%)
  - Security practices (10%)

### 5. Recommendations
- Priority level (CRITICAL/HIGH/MEDIUM/LOW)
- Actionable steps
- Rationale for each recommendation

### 6. Safer Alternatives
- 1-2 alternative products
- Security advantages
- Specific rationale

### 7. Data Sources
- All sources cited with timestamps
- Reproducibility information
- Cache status

## Data Sources

### OpenCVE API
- **URL**: https://www.opencve.io/api
- **Purpose**: CVE vulnerability data
- **Authentication**: None (public API)
- **Rate Limits**: Reasonable use
- **Cache Duration**: 24 hours

### CISA KEV Catalog
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **Purpose**: Known Exploited Vulnerabilities
- **Format**: JSON feed
- **Update Frequency**: Daily
- **Cache Duration**: 1 hour

### ProductHunt API
- **URL**: https://api.producthunt.com/v2/api/graphql
- **Purpose**: Product information and metadata
- **Authentication**: Bearer token
- **Cache Duration**: 24 hours

## Caching and Reproducibility

All assessments are cached in a lightweight JSON file with:
- Full assessment data keyed by the original search term
- Timestamp of creation and updates
- Raw API responses with expiry windows
- Deterministic parameters for reproducibility

### Cache Location
`data/cache.json` (configurable in `.env`)

### Cache Behavior
- Assessments cached for 24 hours (configurable)
- Raw API data cached separately
- Use `use_cache=false` to force fresh assessment
- Automatic cleanup of expired cache entries

## Configuration

Edit `config.py` or use environment variables:

```python
# API Keys
GEMINI_API_KEY=your_key
PRODUCTHUNT_API_KEY=your_key

# Cache settings
CACHE_EXPIRY_HOURS=24
DATABASE_PATH=data/cache.json

# LLM Settings
GEMINI_MODEL=gemini-1.5-pro
GEMINI_TEMPERATURE=0.1  # Low for factual responses
```

## Project Structure

```
hackathon_project/
├── app.py                 # Flask web application
├── assessor.py           # Core assessment engine
├── llm_analyzer.py       # Gemini LLM integration
├── data_sources.py       # API integrations (ProductHunt, OpenCVE, CISA)
├── cache.py              # JSON-based caching layer
├── config.py             # Configuration management
├── requirements.txt      # Python dependencies
├── .env.example         # Environment variables template
├── .gitignore           # Git ignore rules
├── README.md            # This file
├── templates/           # HTML templates
│   ├── base.html       # Base template
│   ├── index.html      # Home page
│   ├── history.html    # Assessment history
│   ├── compare.html    # Product comparison
│   └── error.html      # Error page
└── data/               # Cache directory (created automatically)
  └── cache.json      # JSON cache file
```

## Hallucination Prevention

The system implements several safeguards against LLM hallucinations:

1. **Low Temperature**: Uses temperature=0.1 for factual, consistent responses
2. **Structured Outputs**: All LLM responses are JSON-formatted
3. **Evidence Grounding**: All claims tied to specific data sources
4. **Confidence Levels**: Each analysis includes confidence rating
5. **Data Validation**: Verifies LLM outputs against source data
6. **Insufficient Data Handling**: Returns "Insufficient public evidence" when data is scarce
7. **Source Attribution**: Every finding cites its source
8. **Vendor vs. Independent Claims**: Distinguishes between vendor statements and third-party evidence

## Security Considerations

- API keys stored in `.env` (not committed to git)
- Input validation on all user inputs
- Rate limiting considerations for public APIs
- Local caching reduces external API calls
- No sensitive user data stored
- Read-only operations on public APIs

## Limitations

- **Data Availability**: Assessment quality depends on available public data
- **API Rate Limits**: Public APIs may have rate limits
- **CVE Coverage**: OpenCVE may not have all CVEs immediately
- **ProductHunt Optional**: Works without ProductHunt but with less context
- **Vendor Pages**: Manual vendor security page parsing not yet implemented
- **Real-time Updates**: Cached data may be up to 24 hours old

## Future Enhancements

- [ ] Web scraping for vendor security pages
- [ ] Integration with additional sources (NVD, GitHub Security Advisories)
- [ ] SOC2/ISO attestation verification
- [ ] Bug bounty program detection
- [ ] Terms of Service / Privacy Policy analysis
- [ ] Multi-agent architecture for parallel analysis
- [ ] MCP server implementation for tool integrations
- [ ] Export to PDF/DOCX formats
- [ ] Email report delivery
- [ ] Scheduled re-assessments
- [ ] API key rotation and management

## Troubleshooting

### "Module not found" errors
```bash
pip install -r requirements.txt
```

### "GEMINI_API_KEY not set" warning
Add your Gemini API key to `.env` file

### No CVE data found
- Check vendor name spelling
- Some vendors may not have CVEs in OpenCVE
- Try alternative vendor names

### Database errors
```bash
# Remove and recreate database
rm -rf data/
python app.py  # Will recreate automatically
```

## Support

For issues, questions, or contributions:
1. Check the troubleshooting section
2. Review the API documentation links
3. Check logs in terminal output

## License

This project is built for educational and evaluation purposes.

## Acknowledgments

- Google Gemini API for LLM capabilities
- OpenCVE for vulnerability data
- CISA for KEV catalog
- ProductHunt for product information
- Flask and Python ecosystem

---

**Built for Security Teams | Powered by AI | Grounded in Facts**
 
 
 
 
 
