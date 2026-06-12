const { GoogleGenerativeAI } = require('@google/generative-ai');

// ── Deterministic Score Engine ───────────────────────────────────────────────
// Scoring is computed from REAL data here — Gemini only writes the text fields.
// This eliminates score variance across calls.
function computeBaseScore({ domain, domainInfo, sslInfo, serverLocation }) {
  let score = 50;
  const positive = [];
  const warnings = [];

  // ── SSL (±25) ────────────────────────────────────────────────────────────
  if (sslInfo && !sslInfo.error) {
    if (sslInfo.status === 'Valid') {
      score += 20;
      positive.push(`Valid SSL certificate${sslInfo.issuer ? ` from ${sslInfo.issuer}` : ''}`);
    } else {
      score -= 25;
      warnings.push('SSL certificate is expired or invalid — connection may not be secure');
    }
    if (sslInfo.trusted) {
      score += 5;
      positive.push('Certificate issued by a trusted authority');
    }
    if (sslInfo.daysLeft != null && sslInfo.daysLeft < 14) {
      score -= 10;
      warnings.push(`SSL certificate expiring very soon (${sslInfo.daysLeft} days left)`);
    }
  } else {
    score -= 25;
    warnings.push('No SSL certificate detected — site is not encrypted');
  }

  // ── Domain Age (±20) ─────────────────────────────────────────────────────
  const ageStr = domainInfo?.domainAge || '';
  const ageYears = parseFloat(ageStr) || 0;
  if (ageYears >= 5) {
    score += 20;
    positive.push(`Established domain — ${Math.floor(ageYears)} years old`);
  } else if (ageYears >= 2) {
    score += 12;
    positive.push(`Domain has existed for ${Math.floor(ageYears)} years`);
  } else if (ageYears >= 1) {
    score += 5;
    positive.push(`Domain age: ${Math.floor(ageYears)} year(s)`);
  } else if (ageYears > 0 && ageYears < 0.5) {
    score -= 20;
    warnings.push('Domain is less than 6 months old — significant risk signal');
  } else if (ageYears >= 0.5 && ageYears < 1) {
    score -= 10;
    warnings.push('Domain is less than 1 year old');
  }

  // ── Registrar Reputation (±5) ─────────────────────────────────────────────
  const reputableRegistrars = ['godaddy', 'namecheap', 'cloudflare', 'google', 'markmonitor',
    'network solutions', 'enom', 'tucows', 'amazon', 'porkbun'];
  const registrar = (domainInfo?.registrar || '').toLowerCase();
  if (reputableRegistrars.some(r => registrar.includes(r))) {
    score += 5;
    positive.push(`Registered with a reputable registrar (${domainInfo.registrar})`);
  }

  // ── Hosting Provider (±5) ─────────────────────────────────────────────────
  const reputableHosts = ['digitalocean', 'amazon', 'google', 'cloudflare', 'microsoft',
    'akamai', 'fastly', 'vercel', 'netlify', 'linode', 'vultr', 'hetzner'];
  const isp = (serverLocation?.isp || serverLocation?.org || '').toLowerCase();
  if (reputableHosts.some(h => isp.includes(h))) {
    score += 5;
    positive.push(`Hosted by a known provider (${serverLocation.isp || serverLocation.org})`);
  }

  // ── Server Country (±3) ───────────────────────────────────────────────────
  const highTrustCountries = ['US', 'GB', 'DE', 'NL', 'CA', 'AU', 'SG', 'IN', 'FR', 'JP'];
  if (serverLocation?.countryCode && highTrustCountries.includes(serverLocation.countryCode)) {
    score += 3;
    positive.push(`Server located in ${serverLocation.country || serverLocation.countryCode}`);
  }

  // ── DNSSEC (±5) ───────────────────────────────────────────────────────────
  if (domainInfo?.dnssec === 'Signed' || domainInfo?.dnssec === true) {
    score += 5;
    positive.push('DNSSEC is enabled — domain protected against spoofing');
  } else if (domainInfo?.dnssec === 'Unsigned' || domainInfo?.dnssec === false) {
    score -= 5;
    warnings.push('DNSSEC is unsigned — domain is more susceptible to DNS spoofing attacks');
  }

  // ── Domain Status Flags ───────────────────────────────────────────────────
  const genuinelyBadStatuses = ['pendingdelete', 'redemptionperiod', 'pendingrestore', 'serverhold'];
  const statuses = (domainInfo?.domainStatuses || domainInfo?.status || []);
  const statusList = Array.isArray(statuses) ? statuses : [statuses];
  const hasBadStatus = statusList.some(s =>
    genuinelyBadStatuses.some(bad => s.toLowerCase().includes(bad))
  );
  if (hasBadStatus) {
    score -= 20;
    warnings.push('Domain has critical status flags (pendingDelete or serverHold) indicating potential legal/administrative issues');
  }

  // ── Suspicious TLD (−10) ──────────────────────────────────────────────────
  const suspiciousTLDs = ['.xyz', '.top', '.click', '.gq', '.ml', '.cf', '.tk',
    '.buzz', '.icu', '.shop', '.loan', '.win', '.download'];
  const domainStr = (domainInfo?.domain || domain || '').toLowerCase();
  if (suspiciousTLDs.some(tld => domainStr.endsWith(tld))) {
    score -= 10;
    warnings.push('High-risk domain extension commonly associated with spam or scam websites');
  }

  // ── Known Doc/Dev Subdomain Boost (+10) ──────────────────────────────────
  const knownDocDomains = ['tiangolo.com', 'python.org', 'django-rest-framework.org',
    'readthedocs.io', 'github.io', 'npmjs.com', 'pypi.org', 'docs.rs'];
  if (knownDocDomains.some(d => domainStr.endsWith(d))) {
    score += 10;
    positive.push('Subdomain of a well-known developer platform');
  }

  score = Math.max(0, Math.min(100, score));

  return { score, positive, warnings };
}

function getRiskLevel(score) {
  if (score >= 70) return { riskLevel: 'Low Risk', riskColor: 'green', fraudRisk: 'Low' };
  if (score >= 45) return { riskLevel: 'Medium Risk', riskColor: 'yellow', fraudRisk: 'Medium' };
  return { riskLevel: 'High Risk', riskColor: 'red', fraudRisk: 'High' };
}

function parseJsonSafe(text) {
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) return null;
  try {
    return JSON.parse(jsonMatch[0]);
  } catch (err) {
    return null;
  }
}

async function getAIAnalysis({ domain, serverLocation, domainInfo, sslInfo }) {
  const { score, positive, warnings } = computeBaseScore({ domain, domainInfo, sslInfo, serverLocation });
  const { riskLevel, riskColor, fraudRisk } = getRiskLevel(score);

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'your_gemini_api_key_here') {
    console.log('[GeminiAI] No valid API key found, using rule-based analysis');
    return buildFallbackResponse({ domain, score, riskLevel, riskColor, fraudRisk, positive, warnings });
  }

  console.log('[GeminiAI] Running AI text generation (score already computed)...');

  const genAI = new GoogleGenerativeAI(apiKey);
  const modelNames = ['gemini-1.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash-8b'];
  const prompt = buildPrompt({ domain, serverLocation, domainInfo, sslInfo, lockedScore: score, lockedRiskLevel: riskLevel, positiveSignals: positive, warningSignals: warnings });

  for (const modelName of modelNames) {
    try {
      console.log(`[GeminiAI] Trying model: ${modelName}`);
      const model = genAI.getGenerativeModel({
        model: modelName,
        generationConfig: {
          temperature: 0,
          topP: 1,
          topK: 1,
          maxOutputTokens: 1024,
        },
      });

      const result = await model.generateContent(prompt);
      const text = result.response.text().replace(/```json|```/g, '').trim();
      const parsed = parseJsonSafe(text);
      if (!parsed) throw new Error('No valid JSON found in Gemini response');

      parsed.trustScore = score;
      parsed.riskLevel = riskLevel;
      parsed.riskColor = riskColor;
      parsed.fraudRisk = fraudRisk;
      parsed.positiveSignals = positive;
      parsed.warningSignals = warnings;

      if (!parsed.websitePurpose) {
        parsed.websitePurpose = `${domain} is a website. ${parsed.summary || 'For more details, add GEMINI_API_KEY to your backend .env file.'}`;
      }

      console.log(`[GeminiAI] Success via ${modelName}. Score locked at: ${score}`);
      return parsed;
    } catch (err) {
      console.warn(`[GeminiAI] ${modelName} failed: ${err.message}`);
    }
  }

  console.error('[GeminiAI] All models exhausted. Using rule-based fallback.');
  return buildFallbackResponse({ domain, score, riskLevel, riskColor, fraudRisk, positive, warnings });
}

function buildPrompt({ domain, serverLocation, domainInfo, sslInfo, lockedScore, lockedRiskLevel, positiveSignals, warningSignals }) {
  return `You are WebVerify AI, a cybersecurity analyst. The trust score and risk level below have already been computed from verified data — DO NOT change them. Your only job is to write the text fields.

VERIFIED DATA FOR: ${domain}
- Domain Age: ${domainInfo?.domainAge || 'Unknown'}
- Registrar: ${domainInfo?.registrar || 'Unknown'}
- SSL Status: ${sslInfo?.status || 'Unknown'}
- SSL Issuer: ${sslInfo?.issuer || 'Unknown'}
- SSL Days Left: ${sslInfo?.daysLeft ?? 'Unknown'}
- DNSSEC: ${domainInfo?.dnssec || 'Unknown'}
- Server ISP: ${serverLocation?.isp || serverLocation?.org || 'Unknown'}
- Server Country: ${serverLocation?.country || 'Unknown'}
- Domain Statuses: ${JSON.stringify(domainInfo?.domainStatuses || domainInfo?.status || [])}

LOCKED VALUES (do not change these):
- trustScore: ${lockedScore}
- riskLevel: "${lockedRiskLevel}"
- positiveSignals: ${JSON.stringify(positiveSignals)}
- warningSignals: ${JSON.stringify(warningSignals)}

CRITICAL CONTEXT — READ CAREFULLY:
- Domain statuses "clientTransferProhibited", "clientRenewProhibited", "clientUpdateProhibited", "clientDeleteProhibited" are STANDARD ICANN security locks applied by registrars like GoDaddy to protect legitimate domains. These are COMPLETELY NORMAL and NOT suspicious. Do NOT mention them as risks.
- Only "pendingDelete", "serverHold", "redemptionPeriod" are genuinely alarming.

Respond ONLY with this JSON (no markdown, no backticks, no explanation outside JSON):
{
  "trustScore": ${lockedScore},
  "riskLevel": "${lockedRiskLevel}",
  "riskColor": "${lockedScore >= 70 ? 'green' : lockedScore >= 45 ? 'yellow' : 'red'}",
  "confidence": 92,
  "paymentAdvice": "<one sentence payment recommendation based on the risk level>",
  "summary": "<2-3 sentence professional summary of this website's trustworthiness based on the data above>",
  "websitePurpose": "<one sentence: what does ${domain} likely offer or do, based on the domain name>",
  "positiveSignals": ${JSON.stringify(positiveSignals)},
  "warningSignals": ${JSON.stringify(warningSignals)},
  "fraudRisk": "${lockedScore >= 70 ? 'Low' : lockedScore >= 45 ? 'Medium' : 'High'}",
  "fraudExplanation": "<one paragraph fraud risk explanation — reference the specific data points above>",
  "recommendation": "${lockedScore >= 70 ? 'Safe to use' : lockedScore >= 45 ? 'Use with caution' : 'Avoid'}"
}`;
}

function buildFallbackResponse({ domain, score, riskLevel, riskColor, fraudRisk, positive, warnings }) {
  return {
    trustScore: score,
    riskLevel,
    riskColor,
    confidence: 80,
    paymentAdvice: score >= 70
      ? 'Generally safe for online payments — standard precautions apply.'
      : score >= 45
      ? 'Use a credit card or UPI for buyer protection rather than direct bank transfer.'
      : 'Avoid prepaid payments on this site — prefer Cash on Delivery if available.',
    websitePurpose: `Add GEMINI_API_KEY to .env for AI-powered website purpose detection.`,
    summary: `${domain} has a computed trust score of ${score}/100 based on SSL status, domain age, registrar, and hosting data.`,
    positiveSignals: positive,
    warningSignals: warnings.length ? warnings : ['No major warnings detected'],
    fraudRisk,
    fraudExplanation: score >= 70
      ? 'This website shows strong technical trust signals including valid SSL and established domain age.'
      : score >= 45
      ? 'Some risk factors present. Exercise caution and prefer reversible payment methods like credit cards.'
      : 'Multiple risk signals detected. Avoid sharing payment details until the site can be independently verified.',
    recommendation: score >= 70 ? 'Safe to use' : score >= 45 ? 'Use with caution' : 'Avoid',
  };
}

module.exports = { getAIAnalysis };
