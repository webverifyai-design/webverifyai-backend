# 🛡️ WebShield AI — Backend

Node.js/Express backend for WebShield AI trust analysis.

## What it does
- **Server Location** → `ip-api.com` (free, no key needed)
- **Domain Info** → `rdap.org` ICANN official data (free, no key)
- **SSL Info** → Direct TLS connection + `crt.sh` fallback (free, no key)
- **AI Analysis** → Google Gemini 1.5 Flash (needs your API key)

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
```bash
cp .env.example .env
```
Edit `.env` and add your Gemini API key:
```
GEMINI_API_KEY=your_key_from_aistudio_google_com
PORT=3001
FRONTEND_URL=http://localhost:3000
```
Get your free key at: https://aistudio.google.com/app/apikey

### 3. Run the server
```bash
# Development (auto-reload)
npm run dev

# Production
npm start
```

Server starts at: `http://localhost:3001`

---

## API Endpoints

### `POST /api/analyze` — Full analysis (recommended)
```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"domain": "amazon.com"}'
```

### `GET /api/analyze?domain=amazon.com` — Same, browser-friendly
```bash
curl http://localhost:3001/api/analyze?domain=amazon.com
```

### Individual endpoints
```bash
GET /api/location?domain=amazon.com   # Server location only
GET /api/domain?domain=amazon.com     # Domain WHOIS only
GET /api/ssl?domain=amazon.com        # SSL certificate only
GET /health                           # Health check
```

---

## Response Structure
```json
{
  "domain": "amazon.com",
  "analyzedAt": "2024-01-15T10:30:00.000Z",
  "serverLocation": {
    "ip": "205.251.242.103",
    "city": "Ashburn",
    "country": "United States",
    "isp": "Amazon Technologies Inc.",
    "timezone": "America/New_York"
  },
  "domainInfo": {
    "domain": "amazon.com",
    "registrar": "MarkMonitor Inc.",
    "created": "1 November 1994",
    "expires": "30 October 2025",
    "domainAge": "29 years",
    "dnssec": "Unsigned"
  },
  "sslInfo": {
    "subject": "amazon.com",
    "issuer": "DigiCert Inc",
    "validTo": "22 May 2025",
    "daysLeft": 127,
    "trusted": true,
    "status": "Valid"
  },
  "aiAnalysis": {
    "trustScore": 94,
    "riskLevel": "Low Risk",
    "riskColor": "green",
    "confidence": 97,
    "paymentAdvice": "Safe for online payments",
    "summary": "Amazon.com is one of the most trusted e-commerce platforms globally...",
    "positiveSignals": ["30-year-old domain", "Valid SSL certificate", "Trusted registrar"],
    "warningSignals": [],
    "fraudRisk": "Low",
    "recommendation": "Safe to use"
  }
}
```

---

## Connecting to your React frontend

In your React component:
```javascript
const analyzeWebsite = async (domain) => {
  const response = await fetch('http://localhost:3001/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain })
  });
  const data = await response.json();
  return data;
};
```

For production, replace `http://localhost:3001` with your deployed backend URL.

---

## Deployment (Railway — easiest)
1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Add environment variables: `GEMINI_API_KEY`, `FRONTEND_URL`
4. Railway auto-detects Node.js and deploys
5. Copy the Railway URL and use it in your frontend

## Deployment (Render)
1. Push to GitHub
2. render.com → New Web Service → connect repo
3. Build command: `npm install`
4. Start command: `npm start`
5. Add env vars in Render dashboard
