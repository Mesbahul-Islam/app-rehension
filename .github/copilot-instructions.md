# AI Coding Agent Instructions - Security Assessor

## Project Overview

**Security Assessor** is a Flask-based AI-powered security assessment tool that transforms product names/URLs into CISO-ready trust briefs. It uses Google Gemini LLM with a RAG architecture, fetching data from ProductHunt, NVD CVE, and CISA KEV APIs, scoring products 0-100 on security trustworthiness.

## Critical Architecture Patterns

### Multi-Agent vs Single-Agent Mode
The system supports **two analysis modes** controlled by `USE_MULTI_AGENT` in `.env`:
- **Multi-Agent** (default): Uses 3 specialized agents (Research → Verification → Synthesis) via LangChain
- **Single-Agent**: Direct Gemini API calls for faster, simpler analysis

**Key files**: `multi_agent_analyzer.py`, `llm_analyzer.py`, `config.py`

### Assessment Workflow (6-Step Pipeline)
Located in `assessor.py`, the workflow is:
1. **Entity Resolution**: Parse input → identify product/vendor (Gemini LLM)
2. **Data Gathering**: Fetch from ProductHunt, NVD CVE, CISA KEV APIs
3. **Vulnerability Analysis**: Analyze CVE/KEV data for risk patterns
4. **Trust Scoring**: Rule-based 0-100 score (see `trust_scorer.py`)
5. **Alternative Suggestions**: LLM recommends safer alternatives
6. **Report Compilation**: Generate structured JSON assessment

**Never skip entity resolution** - it determines whether input is product-specific or vendor-only, affecting database queries.

### Evidence Registry Pattern
All LLM analyses MUST cite sources using `evidence.py`:
- Track vendor claims vs independent verification (`source_type`: "vendor" | "independent" | "mixed")
- Every data point gets an evidence ID (`ev_0001`, `ev_0002`, etc.)
- Pass `evidence_registry` to LLM analyzer functions and include `evidence_refs` in responses

**Example**: When adding CVE data, call `evidence_registry.add_independent_claim(source_name="NVD", claim_text=..., url=...)`

### Cache Strategy
`database.py` now stores cached assessments in `data/cache.json` with ~24-hour expiry:
- **Primary lookup**: Original user search term (avoids unnecessary API calls)
- **Secondary lookup**: Normalized `product_name` OR `vendor` after entity resolution
- **Raw data cache**: API payloads stored separately with their own TTL
Ensure cache is checked before calling external APIs.

### Flask Progress Streaming
Real-time progress uses Server-Sent Events (SSE):
- `app.py`: POST `/assess` starts assessment, returns `session_id`
- Frontend connects to `/progress/<session_id>` for live updates
- Use `progress_callback` parameter in `assess_product()` to emit stage updates

**Stages**: `initialization`, `entity_resolution`, `data_gathering`, `security_data`, `llm_analysis`, `trust_scoring`, `report_compilation`

## Development Workflows

### Running the Application
```bash
source venv/bin/activate  # Always activate venv first
python app.py             # Starts Flask on http://localhost:5000
```

### Testing Programmatically
Use `example_usage.py` as a template:
```bash
python example_usage.py   # Assesses Slack, Teams, Zoom; saves JSON results
```

### API Testing
```bash
curl -X POST http://localhost:5000/assess \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Slack", "use_cache": true}'
```

### Debugging Cache
```bash
cat data/cache.json        # Inspect cached assessments
jq '.assessments | length' data/cache.json
```

## Project-Specific Conventions

### LLM Response Format
**All LLM responses MUST be valid JSON**. Strip markdown code blocks:
```python
text = response.text.strip()
if text.startswith("```json"):
    text = text.split("```json")[1].split("```")[0].strip()
result = json.loads(text)
```

### Trust Score Weighting (Fixed)
From `trust_scorer.py`, weights are hardcoded and MUST sum to 100:
- Vulnerability History: 30 points
- KEV Presence: 25 points  
- Product Maturity: 15 points
- Security Practices: 15 points
- Incident Signals: 10 points
- Data Compliance: 5 points

**Never modify weights** without adjusting all components to sum to 100.

### Error Handling Pattern
Always include confidence levels in uncertain analyses:
```python
{
    "product_name": "Unknown Product",
    "confidence": "low",  # "high" | "medium" | "low"
    "reason": "No data found in ProductHunt or NVD"
}
```

### API Rate Limits
- **NVD API**: 5 requests/30s (unauthenticated) or 50 requests/30s (with `NVD_API_KEY`)
- **ProductHunt**: 100 requests/hour
- Use `time.sleep()` in `data_sources.py` to respect limits

## Key Integration Points

### External APIs (data_sources.py)
- `ProductHuntAPI`: GraphQL API, requires Bearer token
- `NVDAPI`: REST API, uses `?cpeName=` query param for vendor search
- `CISAKEVAPI`: JSON feed, no auth required, returns list of Known Exploited Vulnerabilities

### Frontend JavaScript (static/js/)
- `form-handler.js`: Submits `/assess`, connects to progress stream
- `progress-tracker.js`: Updates UI stages dynamically
- `assessment-display.js`: Renders assessment JSON with trust score visualization

### LangChain Agents (multi_agent_analyzer.py)
Uses LangChain v1.0 with `ChatGoogleGenerativeAI`:
- Research Agent: Analyzes data, generates initial report WITH citations
- Verification Agent: Cross-checks facts, validates URLs
- Synthesis Agent: Compiles final verified report with confidence scores

## Common Gotchas

1. **Vendor-only vs Product-specific**: After entity resolution, check if `product_name` is `null` (vendor-only) before querying databases
2. **Session IDs**: Frontend generates `Date.now().toString()` for progress tracking - use same ID for both `/assess` and `/progress/<session_id>`
3. **Environment Variables**: `.env` file is gitignored. Always copy from `.env.example` and add API keys
4. **LLM Temperature**: Set to 0.1 for factual consistency (see `config.py` and `llm_analyzer.py`)
5. **Cache Path Permissions**: Ensure `data/cache.json` is writable; the cache auto-creates directories if missing

## File Purpose Quick Reference

| File | Purpose |
|------|---------|
| `app.py` | Flask routes, SSE progress streaming |
| `assessor.py` | Main orchestration (6-step workflow) |
| `llm_analyzer.py` | Single-agent Gemini integration |
| `multi_agent_analyzer.py` | LangChain multi-agent system |
| `trust_scorer.py` | Rule-based 0-100 scoring algorithm |
| `evidence.py` | Source citation and evidence tracking |
| `database.py` | JSON caching with 24h expiry |
| `data_sources.py` | API clients for ProductHunt, NVD, CISA |
| `input_parser.py` | Detect input format (product/URL/SHA1) |
| `config.py` | Environment variables and constants |

## When Adding New Features

- **New data source**: Add to `data_sources.py`, update `assessor._gather_*_data()`, add evidence citations
- **New trust score component**: Update `trust_scorer.py` weights (ensure sum=100), add explanation method
- **New LLM analysis**: Add to both `llm_analyzer.py` (single-agent) and `multi_agent_analyzer.py` (multi-agent)
- **New API endpoint**: Add to `app.py`, update `API.md`, add frontend handler in `static/js/`
