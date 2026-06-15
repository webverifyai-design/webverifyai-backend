const express = require('express');
const router = express.Router();

const { getServerLocation } = require('../services/serverLocation');
const { getDomainInfo } = require('../services/domainInfo');
const { getSSLInfo } = require('../services/sslInfo');
const { getAIAnalysis } = require('../services/geminiAnalysis');
const { getThreatIntelligence } = require('../services/threatIntelligence');
const { getDNSSecurityCheck } = require('../services/dnsSecurityCheck');
const { getContentAnalysis } = require('../services/contentAnalysis');

/**
 * POST /api/analyze
 * Body: { "domain": "example.com" }
 * 
 * Runs all checks in parallel, then passes to Gemini for AI analysis
 */
router.post('/analyze', async (req, res) => {
  const { domain } = req.body;

  if (!domain || typeof domain !== 'string') {
    return res.status(400).json({ error: 'domain is required in request body' });
  }

  // Clean domain input
  const cleanDomain = domain
    .trim()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .toLowerCase();

  if (!cleanDomain || cleanDomain.length < 3) {
    return res.status(400).json({ error: 'Invalid domain name' });
  }

  console.log(`[Analyze] Starting analysis for: ${cleanDomain}`);

  try {
    // Run all data fetches in parallel for speed
    const [serverLocation, domainInfo, sslInfo, threatIntelligence, dnsSecurityCheck, contentAnalysis] = await Promise.all([
      getServerLocation(cleanDomain),
      getDomainInfo(cleanDomain),
      getSSLInfo(cleanDomain),
      getThreatIntelligence(cleanDomain),
      getDNSSecurityCheck(cleanDomain),
      getContentAnalysis(cleanDomain),
    ]);

    // Check if domain exists — multiple indicators including DNS NS records
    console.log(`[Analyze] Checking domain existence for: ${cleanDomain}`);
    console.log(`[Analyze] domainInfo.error: ${domainInfo.error}`);
    console.log(`[Analyze] serverLocation.country: ${serverLocation.country}`);
    console.log(`[Analyze] DNS MX Records: ${JSON.stringify(dnsSecurityCheck.mxRecords)}`);

    const hasValidDomainInfo = !domainInfo.error && domainInfo.domain && domainInfo.domain !== 'Unknown';
    const hasValidServerLocation = serverLocation.country && serverLocation.country !== 'Unknown';
    const hasMXRecords = dnsSecurityCheck.mxRecords && dnsSecurityCheck.mxRecords.exists;

    // Domain NOT found if ANY of these are true:
    // 1. domainInfo explicitly has error flag, OR
    // 2. No valid domain registration AND no server location, OR
    // 3. No domain registration AND no MX records (indicates unregistered domain)
    if (domainInfo.error || (!hasValidDomainInfo && !hasValidServerLocation) || (!hasValidDomainInfo && !hasMXRecords)) {
      console.warn(`[Analyze] ❌ Domain not found: ${cleanDomain}`);
      console.log(`[Analyze] Reasons - error:${domainInfo.error}, validDomainInfo:${hasValidDomainInfo}, validServer:${hasValidServerLocation}, hasMX:${hasMXRecords}`);
      return res.status(404).json({
        notFound: true,
        domain: cleanDomain,
        error: 'Website not found',
        detail: `The domain "${cleanDomain}" does not appear to exist or is unreachable`,
        aiAnalysis: {
          simpleSummary: `The domain "${cleanDomain}" does not appear to exist or is unreachable.`,
        },
      });
    }

    console.log(`[Analyze] Data collected. Running AI analysis...`);

    // Run Gemini AI analysis with all collected data
    const aiAnalysis = await getAIAnalysis({
      domain: cleanDomain,
      serverLocation,
      domainInfo,
      sslInfo,
      threatIntelligence,
      dnsSecurityCheck,
      contentAnalysis,
    });

    console.log(`[Analyze] Complete. Trust score: ${aiAnalysis.trustScore}`);

    // Return full response
    return res.json({
      domain: cleanDomain,
      analyzedAt: new Date().toISOString(),
      serverLocation,
      domainInfo,
      sslInfo,
      threatIntelligence,
      dnsSecurityCheck,
      contentAnalysis,
      aiAnalysis,
    });

  } catch (err) {
    console.error(`[Analyze] Fatal error for ${cleanDomain}:`, err.message);
    return res.status(500).json({
      error: 'Analysis failed',
      detail: err.message,
      domain: cleanDomain,
    });
  }
});

/**
 * GET /api/analyze?domain=example.com
 * GET version for easy browser testing
 */
router.get('/analyze', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) {
    return res.status(400).json({ error: 'domain query parameter required', example: '/api/analyze?domain=google.com' });
  }
  req.body = { domain };
  const cleanDomain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  try {
    const [serverLocation, domainInfo, sslInfo, threatIntelligence, dnsSecurityCheck, contentAnalysis] = await Promise.all([
      getServerLocation(cleanDomain),
      getDomainInfo(cleanDomain),
      getSSLInfo(cleanDomain),
      getThreatIntelligence(cleanDomain),
      getDNSSecurityCheck(cleanDomain),
      getContentAnalysis(cleanDomain),
    ]);

    // Check if domain exists — multiple indicators including DNS records
    console.log(`[Analyze GET] Checking domain existence for: ${cleanDomain}`);
    console.log(`[Analyze GET] domainInfo.error: ${domainInfo.error}`);
    console.log(`[Analyze GET] serverLocation.country: ${serverLocation.country}`);
    console.log(`[Analyze GET] DNS MX Records: ${JSON.stringify(dnsSecurityCheck.mxRecords)}`);

    const hasValidDomainInfo = !domainInfo.error && domainInfo.domain && domainInfo.domain !== 'Unknown';
    const hasValidServerLocation = serverLocation.country && serverLocation.country !== 'Unknown';
    const hasMXRecords = dnsSecurityCheck.mxRecords && dnsSecurityCheck.mxRecords.exists;

    // Domain NOT found if ANY of these are true:
    // 1. domainInfo explicitly has error flag, OR
    // 2. No valid domain registration AND no server location, OR
    // 3. No domain registration AND no MX records (indicates unregistered domain)
    if (domainInfo.error || (!hasValidDomainInfo && !hasValidServerLocation) || (!hasValidDomainInfo && !hasMXRecords)) {
      console.warn(`[Analyze GET] ❌ Domain not found: ${cleanDomain}`);
      console.log(`[Analyze GET] Reasons - error:${domainInfo.error}, validDomainInfo:${hasValidDomainInfo}, validServer:${hasValidServerLocation}, hasMX:${hasMXRecords}`);
      return res.status(404).json({
        notFound: true,
        domain: cleanDomain,
        error: 'Website not found',
        detail: `The domain "${cleanDomain}" does not appear to exist or is unreachable`,
        aiAnalysis: {
          simpleSummary: `The domain "${cleanDomain}" does not appear to exist or is unreachable.`,
        },
      });
    }
          simpleSummary: `The domain "${cleanDomain}" does not appear to exist or is unreachable.`,
        },
      });
    }

    const aiAnalysis = await getAIAnalysis({
      domain: cleanDomain,
      serverLocation,
      domainInfo,
      sslInfo,
      threatIntelligence,
      dnsSecurityCheck,
      contentAnalysis,
    });

    return res.json({
      domain: cleanDomain,
      analyzedAt: new Date().toISOString(),
      serverLocation,
      domainInfo,
      sslInfo,
      threatIntelligence,
      dnsSecurityCheck,
      contentAnalysis,
      aiAnalysis,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/location?domain=example.com
 * Individual endpoint — Server Location only
 */
router.get('/location', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getServerLocation(domain.replace(/^https?:\/\//, '').replace(/\/.*$/, ''));
  res.json(result);
});

/**
 * GET /api/domain?domain=example.com
 * Individual endpoint — Domain Info only
 */
router.get('/domain', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getDomainInfo(domain);
  res.json(result);
});

/**
 * GET /api/ssl?domain=example.com
 * Individual endpoint — SSL Info only
 */
router.get('/ssl', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getSSLInfo(domain);
  res.json(result);
});

/**
 * GET /api/threat?domain=example.com
 * Individual endpoint — Threat Intelligence only
 */
router.get('/threat', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getThreatIntelligence(domain);
  res.json(result);
});

/**
 * GET /api/dns?domain=example.com
 * Individual endpoint — DNS Security only
 */
router.get('/dns', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getDNSSecurityCheck(domain);
  res.json(result);
});

/**
 * GET /api/content?domain=example.com
 * Individual endpoint — Content Analysis only
 */
router.get('/content', async (req, res) => {
  const domain = req.query.domain;
  if (!domain) return res.status(400).json({ error: 'domain required' });
  const result = await getContentAnalysis(domain);
  res.json(result);
});

/**
 * POST /api/share
 * Log share events for analytics
 */
router.post('/share', async (req, res) => {
  const { domain, platform, trustScore } = req.body;

  if (!domain || !platform) {
    return res.status(400).json({ error: 'domain and platform required' });
  }

  console.log(`[Share] Domain: ${domain}, Platform: ${platform}, Score: ${trustScore}, Time: ${new Date().toISOString()}`);

  res.json({
    success: true,
    message: `Shared ${domain} on ${platform}`,
    timestamp: new Date().toISOString(),
  });
});

module.exports = router;
