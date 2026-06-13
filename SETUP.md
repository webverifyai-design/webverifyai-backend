# WebVerify Security Features - Setup Guide

## ✅ Implementation Complete

All 6 security features have been successfully integrated into WebVerify:

### 1. **Google Safe Browsing** ✓
- Checks domain against Google's malware/phishing database
- File: `src/services/threatIntelligence.js`
- Requires: `GOOGLE_SAFE_BROWSING_API_KEY` in `.env`

### 2. **OpenPhish** ✓
- Community phishing URL detection
- File: `src/services/threatIntelligence.js`
- Requires: No API key (free API)

### 3. **PhishTank** ✓
- Phishing database checks
- File: `src/services/threatIntelligence.js`
- Requires: `PHISHTANK_API_KEY` in `.env` (optional)

### 4. **DNS Security (DNSSEC + MX + SPF)** ✓
- DNSSEC validation
- MX record verification
- SPF record checking
- File: `src/services/dnsSecurityCheck.js`
- Requires: No API key (uses Node.js DNS)

### 5. **Content Analysis** ✓
- Website HTML analysis
- Suspicious pattern detection
- Contact info validation
- File: `src/services/contentAnalysis.js`
- Requires: No API key

### 6. **URLhaus** ✓
- Malicious URL database checks
- File: `src/services/threatIntelligence.js`
- Requires: No API key (free API)

## Setup Instructions

### Step 1: Create .env file
```bash
cp .env.example .env
```

### Step 2: Add API Keys
Edit `.env` and add your keys:
```
GOOGLE_SAFE_BROWSING_API_KEY=your_key_here
PHISHTANK_API_KEY=your_key_here (optional)
GEMINI_API_KEY=your_key_here
```

### Step 3: Install Dependencies
```bash
npm install
```

### Step 4: Start Backend
```bash
npm run dev
```

### Step 5: Start Frontend
```bash
cd ../webverifyai
npm run dev
```

## API Endpoints

### Main Analysis
- `POST /api/analyze` - Full analysis with all checks
- `GET /api/analyze?domain=example.com` - Full analysis (GET version)

### Individual Checks
- `GET /api/threat?domain=example.com` - Threat intelligence only
- `GET /api/dns?domain=example.com` - DNS security only
- `GET /api/content?domain=example.com` - Content analysis only
- `GET /api/location?domain=example.com` - Server location
- `GET /api/domain?domain=example.com` - Domain info
- `GET /api/ssl?domain=example.com` - SSL info

## Response Format

All endpoints return threat intelligence, DNS checks, and content analysis data:

```json
{
  "domain": "example.com",
  "threatIntelligence": {
    "googleSafeBrowsing": { "threat": false },
    "phishTank": { "threat": false },
    "openPhish": { "threat": false },
    "urlhaus": { "threat": false }
  },
  "dnsSecurityCheck": {
    "dnssec": { "status": "unknown", "signed": false },
    "mxRecords": { "exists": true, "count": 2, "quality": "good" },
    "spfRecord": { "exists": true, "valid": true },
    "tlsaRecords": { "exists": false }
  },
  "contentAnalysis": {
    "statusCode": 200,
    "suspiciousPatterns": [],
    "hasContactInfo": true,
    "redirects": 0
  },
  "aiAnalysis": { ... }
}
```

## Files Modified

### Backend
- ✅ `src/services/threatIntelligence.js` (NEW)
- ✅ `src/services/dnsSecurityCheck.js` (NEW)
- ✅ `src/services/contentAnalysis.js` (NEW)
- ✅ `src/routes/analyze.js` (UPDATED)
- ✅ `src/services/geminiAnalysis.js` (UPDATED)
- ✅ `.env.example` (NEW)

### Frontend
- ✅ `lib/types.ts` (UPDATED)
- ✅ `lib/api.ts` (UPDATED)

## Security Notes

⚠️ **CRITICAL**: The Google API key you shared publicly must be immediately revoked in Google Cloud Console and replaced with a new one.

1. Go to https://console.cloud.google.com
2. Delete the exposed API key
3. Generate a new key
4. Add to `.env` file

## Scoring Changes

The trust score now includes:
- **+5**: SPF record configured
- **+3**: Multiple MX records
- **+2**: TLSA records (DANE)
- **-25**: Each threat database hit (Google Safe Browsing, PhishTank, OpenPhish, URLhaus)
- **-3 to -15**: Suspicious content patterns
- **-5**: Missing contact information

## Testing

Test with safe domains:
```
curl http://localhost:3001/api/analyze?domain=google.com
curl http://localhost:3001/api/analyze?domain=github.com
```

Test individual endpoints:
```
curl http://localhost:3001/api/threat?domain=google.com
curl http://localhost:3001/api/dns?domain=google.com
curl http://localhost:3001/api/content?domain=google.com
```

## Performance

All checks run in parallel (Promise.all) for optimal performance:
- Total analysis time: ~8-15 seconds
- Each service has 8-10 second timeout
- Graceful fallback if any API fails

## Troubleshooting

1. **No threat data in response**: Check API keys in `.env`
2. **DNS errors**: Some ISPs block DNS queries - ensure UDP port 53 is open
3. **Slow responses**: Check internet connection and API rate limits
4. **CORS errors**: Frontend URL must be in backend CORS whitelist

## Rate Limiting

- Google Safe Browsing: 600/min
- PhishTank: Free tier has rate limits
- URLhaus: No known rate limit
- OpenPhish: Free API
- DNS: No rate limit (local)

Implement caching in production for high traffic.
