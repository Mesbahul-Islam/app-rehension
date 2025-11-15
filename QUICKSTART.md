# Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Run Setup Script
```bash
./setup.sh
```

This will:
- Create a virtual environment
- Install all dependencies
- Create `.env` file from template

### Step 2: Add API Keys

Edit the `.env` file and add your Gemini API key:

```bash
nano .env
```

**Required:**
- `GEMINI_API_KEY`: Get from https://makersuite.google.com/app/apikey

**Optional:**
- `PRODUCTHUNT_API_KEY`: Get from https://api.producthunt.com/v2/docs

### Step 3: Start the Application

```bash
source venv/bin/activate
python app.py
```

Then open your browser to: **http://localhost:5000**

---

## 🧪 Test the System

### Option 1: Use the Web Interface
1. Go to http://localhost:5000
2. Enter a product name (e.g., "Slack", "Docker", "VSCode")
3. Click "Generate Assessment"
4. Wait 30-60 seconds for results

### Option 2: Run Example Script
```bash
python example_usage.py
```

This will assess Slack, Microsoft Teams, and Zoom, and save results to JSON files.

### Option 3: Use API Directly
```bash
curl -X POST http://localhost:5000/assess \
  -H "Content-Type: application/json" \
  -d '{"input_text": "Slack", "use_cache": true}'
```

---

## 📊 What You'll Get

Each assessment includes:

1. **Entity Information** - Product name, vendor, URLs
2. **Classification** - Category and use cases
3. **Security Posture** - CVEs, KEVs, vulnerability trends
4. **Trust Score** - 0-100 score with detailed breakdown
5. **Recommendations** - Actionable security guidance
6. **Alternatives** - Safer product suggestions
7. **Sources** - All data sources cited

---

## 🔍 Example Products to Try

- **Communication**: Slack, Microsoft Teams, Discord, Zoom
- **Development**: Docker, GitHub, GitLab, VSCode
- **Cloud**: AWS, Azure, Heroku, DigitalOcean
- **Security**: 1Password, LastPass, Okta, Auth0
- **AI Tools**: ChatGPT, Claude, Gemini, Copilot

---

## 🎯 Key Features to Explore

### 1. Compare Products
- Go to `/compare`
- Enter 2-3 competing products
- See side-by-side security comparison

### 2. View History
- Go to `/history`
- See all past assessments
- Check trust scores at a glance

### 3. Cached Results
- First assessment takes 30-60 seconds
- Cached results return instantly
- Cache expires after 24 hours
- Uncheck "Use cached results" to force fresh data

---

## 🐛 Troubleshooting

### "GEMINI_API_KEY not set"
- Add your key to `.env` file
- Restart the application

### No CVE Data Found
- Normal for some products/vendors
- Try alternative vendor names
- Check logs for API errors

### Assessment Takes Too Long
- First run is slower (fetching data)
- Subsequent runs use cache
- Check internet connection
- OpenCVE API may be slow for popular vendors

### Import Errors
```bash
pip install -r requirements.txt
```

---

## 📁 Project Structure

```
hackathon_project/
├── app.py              # Flask web app
├── assessor.py         # Main assessment engine
├── llm_analyzer.py     # Gemini LLM integration
├── data_sources.py     # API clients
├── database.py         # JSON caching
├── config.py           # Configuration
├── templates/          # HTML templates
└── data/              # JSON cache file (auto-created)
```

---

## 🎓 Understanding the Output

### Trust Score Interpretation
- **80-100**: Excellent security posture, low risk
- **60-79**: Good security, acceptable risk
- **40-59**: Moderate concerns, requires review
- **0-39**: Significant concerns, high risk

### Risk Levels
- **LOW**: Safe to approve with standard review
- **MEDIUM**: Requires security assessment
- **HIGH**: Needs remediation plan
- **CRITICAL**: Do not approve without thorough review

### CVE Severity
- **CRITICAL**: Immediate action required
- **HIGH**: Prompt patching needed
- **MEDIUM**: Plan for patching
- **LOW**: Monitor and plan

---

## 🚀 Next Steps

1. ✅ Assess your first product
2. ✅ Compare alternatives
3. ✅ Review assessment history
4. ✅ Share results with your team
5. ✅ Integrate into your approval process

---

## 📚 More Information

- Full documentation: See `README.md`
- OpenCVE API docs: https://docs.opencve.io/api/
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Gemini API: https://ai.google.dev/docs

---

**Happy Assessing! 🛡️**
