// webshieldApi.js
// Drop this file into your React src/ folder and import it in your components
//
// Usage:
//   import { analyzeWebsite } from './webshieldApi';
//   const result = await analyzeWebsite('amazon.com');

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || 'http://localhost:3001';

/**
 * Full WebShield analysis — calls backend which runs all checks + Gemini AI
 * @param {string} domain - Domain to analyze e.g. "amazon.com"
 * @returns {Promise<WebShieldResult>}
 */
export async function analyzeWebsite(domain) {
  const cleanDomain = domain
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '');

  const response = await fetch(`${BACKEND_URL}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: cleanDomain }),
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    throw new Error(err.error || `Server error: ${response.status}`);
  }

  return response.json();
}

/**
 * Get server location only (faster, no AI)
 * @param {string} domain
 */
export async function getServerLocation(domain) {
  const r = await fetch(`${BACKEND_URL}/api/location?domain=${encodeURIComponent(domain)}`);
  return r.json();
}

/**
 * Get domain WHOIS info only
 * @param {string} domain
 */
export async function getDomainInfo(domain) {
  const r = await fetch(`${BACKEND_URL}/api/domain?domain=${encodeURIComponent(domain)}`);
  return r.json();
}

/**
 * Get SSL certificate info only
 * @param {string} domain
 */
export async function getSSLInfo(domain) {
  const r = await fetch(`${BACKEND_URL}/api/ssl?domain=${encodeURIComponent(domain)}`);
  return r.json();
}

/**
 * Health check — verify backend is running
 */
export async function checkBackendHealth() {
  try {
    const r = await fetch(`${BACKEND_URL}/health`);
    return r.ok;
  } catch {
    return false;
  }
}

// ── TypeScript types (for reference, rename file to .ts if using TS) ──
//
// interface ServerLocation { ip, city, region, country, timezone, isp, org, asn, lat, lon }
// interface DomainInfo { domain, registrar, created, updated, expires, nameservers, status, domainAge, dnssec }
// interface SSLInfo { subject, issuer, validFrom, validTo, daysLeft, trusted, status, fingerprint }
// interface AIAnalysis { trustScore, riskLevel, riskColor, confidence, paymentAdvice, summary,
//                        positiveSignals, warningSignals, fraudRisk, fraudExplanation, recommendation }
// interface WebShieldResult { domain, analyzedAt, serverLocation, domainInfo, sslInfo, aiAnalysis }
