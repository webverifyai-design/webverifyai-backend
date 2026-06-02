const { GoogleGenerativeAI } = require('@google/generative-ai');

/**
 * Run AI trust analysis using Google Gemini
 * Takes all collected data and returns structured trust analysis
 */
async function getAIAnalysis({ domain, serverLocation, domainInfo, sslInfo }) {
  const apiKey = process.env.GEMINI_API_KEY;

  // Check if API key is configured and valid
  if (!apiKey || apiKey === 'your_gemini_api_key_here') {
    console.log('[GeminiAI] No valid API key found, using rule-based analysis');
    return getRuleBasedAnalysis({ domain, domainInfo, sslInfo });
  }

  console.log('[GeminiAI] Attempting to use Gemini API for analysis...');
  const { GoogleGenerativeAI } = require('@google/generative-ai');
  const genAI = new GoogleGenerativeAI(apiKey);

  // Models to try in order of preference
  const modelNames = ['gemini-2.5-flash', 'gemini-3.5-flash', 'gemini-2.5-flash-8b'];
  const prompt = buildPrompt({ domain, serverLocation, domainInfo, sslInfo });

  // ── True Model Fallback Loop ─────────────────────────────────────────────
  for (const modelName of modelNames) {
    try {
      console.log(`[GeminiAI] Testing model: ${modelName}`);
      const model = genAI.getGenerativeModel({ model: modelName });
      
      // We must call the API INSIDE the loop so errors are caught here
      const result = await model.generateContent(prompt);
      const text = result.response.text();

      // Parse JSON from Gemini response
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (!jsonMatch) throw new Error('No JSON in Gemini response');

      const parsed = JSON.parse(jsonMatch[0]);
      
      // Ensure websitePurpose is included
      if (!parsed.websitePurpose) {
        parsed.websitePurpose = `${domain} is a website. ${parsed.summary || 'For more details, add GEMINI_API_KEY to your backend .env file.'}`;
      }

      console.log(`[GeminiAI] Successfully received AI analysis from ${modelName}`);
      return parsed;

    } catch (err) {
      // If it's a 429 (Quota) or 503 (High Demand), log it and try the next model
      console.warn(`[GeminiAI] ${modelName} failed. Reason: ${err.message}. Trying next model...`);
    }
  }

  // ── Ultimate Fallback ────────────────────────────────────────────────────
  // If the loop finishes and ALL models failed or hit quotas, fall back gracefully
  console.error('[GeminiAI] All Gemini models exhausted or rate-limited. Using rule-based analysis.');
  return getRuleBasedAnalysis({ domain, domainInfo, sslInfo });
}

function buildPrompt({ domain, serverLocation, domainInfo, sslInfo }) {
  return `You are WebVerify AI, a website trust and safety analyzer. Analyze this website and respond ONLY with a valid JSON object.

Domain: ${domain}

Server Location Data:
${JSON.stringify(serverLocation, null, 2)}

Domain Registration Data:
${JSON.stringify(domainInfo, null, 2)}

SSL Certificate Data:
${JSON.stringify(sslInfo, null, 2)}

Based on the above data, respond with ONLY this JSON structure (no markdown, no explanation):
{
  "trustScore": <number 0-100>,
  "riskLevel": "<Low Risk | Medium Risk | High Risk>",
  "riskColor": "<green | yellow | red>",
  "confidence": <number 0-100>,
  "paymentAdvice": "<one sentence payment recommendation>",
  "summary": "<2-3 sentence professional summary of this website's trustworthiness>",
  "websitePurpose": "<one sentence description of what this website does, or its primary purpose>",
  "positiveSignals": ["<signal 1>", "<signal 2>", "<signal 3>"],
  "warningSignals": ["<warning 1>", "<warning 2>"],
  "fraudRisk": "<Low | Medium | High>",
  "fraudExplanation": "<one paragraph fraud risk explanation and payment recommendation>",
  "recommendation": "<Safe to use | Use with caution | Avoid>"
}

Rules:
- trustScore should reflect: domain age (older = higher), SSL validity, known hosting provider, DNSSEC
- If domain age > 5 years AND SSL valid: trustScore >= 70
- If domain age < 1 year: trustScore <= 50, riskLevel = High Risk
- If SSL expired or missing: major penalty
- Be specific and professional
- For websitePurpose: use your training knowledge about the domain to describe what it does or provide a brief functional description`;
}

/**
 * Rule-based analysis fallback when Gemini API is unavailable
 */
function getRuleBasedAnalysis({ domain, domainInfo, sslInfo }) {
  let score = 55; // start higher as baseline
  const positive = [];
  const warnings = [];

  // ── Domain age scoring ──────────────────────────────
  const ageStr = domainInfo?.domainAge || '';
  const ageYears = parseInt(ageStr) || 0;
  if (ageYears >= 10) { score += 20; positive.push(`Established domain — ${ageYears} years old`); }
  else if (ageYears >= 5) { score += 15; positive.push(`Domain age: ${ageYears} years`); }
  else if (ageYears >= 2) { score += 10; positive.push(`Domain age: ${ageYears} years`); }
  else if (ageYears >= 1) { score += 5; }
  else if (ageYears < 1) { score -= 15; warnings.push('Very new domain — less than 1 year old'); }

  // ── SSL scoring ─────────────────────────────────────
  if (sslInfo && !sslInfo.error) {
    if (sslInfo.status === 'Valid') { score += 15; positive.push('Valid SSL certificate'); }
    else { score -= 15; warnings.push('SSL certificate expired or invalid'); }
    if (sslInfo.trusted) { score += 5; positive.push('Certificate from trusted authority'); }
    if (sslInfo.daysLeft > 60) positive.push(`SSL valid for ${sslInfo.daysLeft} more days`);
    else if (sslInfo.daysLeft < 14) warnings.push('SSL certificate expiring very soon');
  } else {
    score -= 20;
    warnings.push('No SSL certificate detected');
  }

  // ── DNSSEC ──────────────────────────────────────────
  if (domainInfo?.dnssec === 'Signed') { score += 5; positive.push('DNSSEC enabled'); }

  // ── Known trusted registrars ─────────────────────────
  const trustedRegistrars = ['markmonitor', 'godaddy', 'namecheap', 'cloudflare', 'google', 'amazon'];
  const reg = (domainInfo?.registrar || '').toLowerCase();
  if (trustedRegistrars.some(r => reg.includes(r))) {
    score += 5;
    positive.push(`Registered with ${domainInfo.registrar}`);
  }

  // ── Known trusted hosting orgs ───────────────────────
  // Subdomains of well-known projects/CDNs get a boost
  const trustedOrgs = ['cloudflare', 'amazon', 'google', 'microsoft', 'fastly', 'github', 'vercel', 'netlify'];
  // (serverLocation not passed here, but domainInfo registrar helps)

  // ── Subomain of well-known domain ───────────────────
  // e.g. fastapi.tiangolo.com, docs.python.org — docs/subdomain pattern
  const domainStr = (domainInfo?.domain || domain || '').toLowerCase();
  const knownDocDomains = ['tiangolo.com', 'python.org', 'django-rest-framework.org',
    'readthedocs.io', 'github.io', 'npmjs.com', 'pypi.org', 'docs.rs'];
  if (knownDocDomains.some(d => domainStr.endsWith(d))) {
    score += 10;
    positive.push('Subdomain of a well-known developer platform');
  }

  score = Math.min(100, Math.max(0, score));

  const riskLevel = score >= 70 ? 'Low Risk' : score >= 45 ? 'Medium Risk' : 'High Risk';
  const riskColor = score >= 70 ? 'green' : score >= 45 ? 'yellow' : 'red';

  return {
    trustScore: score,
    riskLevel,
    riskColor,
    confidence: 75,
    paymentAdvice: score >= 70
      ? 'Generally safe for online payments'
      : score >= 45
      ? 'Use credit card or UPI for protection'
      : 'Avoid online payments on this site',
    websitePurpose: `Gemini AI is required for website purpose detection. Add GEMINI_API_KEY to your backend .env file.`,  
    summary: `${domain} has a trust score of ${score}/100. ${ageYears > 0 ? `Domain is ${ageYears} years old.` : ''} ${sslInfo?.status === 'Valid' ? 'SSL certificate is valid and trusted.' : 'SSL status needs attention.'}`,
    positiveSignals: positive,
    warningSignals: warnings.length ? warnings : ['No major warnings detected'],
    fraudRisk: score >= 70 ? 'Low' : score >= 45 ? 'Medium' : 'High',
    fraudExplanation: score >= 70
      ? 'This website shows strong technical signals of legitimacy.'
      : 'Exercise caution. Prefer reversible payment methods like credit cards or UPI.',
    recommendation: score >= 70 ? 'Safe to use' : score >= 45 ? 'Use with caution' : 'Avoid',
  };
}

/**
 * Mock response for when no API key is set (dev/demo mode)
 */
function getMockAnalysis({ domain }) {
  return {
    trustScore: 72,
    riskLevel: 'Medium Risk',
    riskColor: 'yellow',
    confidence: 85,
    paymentAdvice: 'Use credit card or UPI for buyer protection',
    websitePurpose: `Website purpose detection requires Gemini AI. Add your GEMINI_API_KEY to the backend .env file for real AI-powered analysis.`,
    summary: `Analysis for ${domain} — Add your GEMINI_API_KEY in .env for real AI-powered analysis. This is a demo response showing the data structure.`,
    positiveSignals: ['HTTPS Enabled', 'Domain Age: Multiple Years', 'Valid SSL Certificate'],
    warningSignals: ['Add Gemini API key for full AI analysis'],
    fraudRisk: 'Medium',
    fraudExplanation: 'This is a demo response. Add your Google Gemini API key in the .env file for real AI-powered trust analysis.',
    recommendation: 'Use with caution',
    _demo: true,
  };
}

module.exports = { getAIAnalysis };
