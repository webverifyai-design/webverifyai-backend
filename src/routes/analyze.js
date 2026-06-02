const express = require('express');
const router = express.Router();

const { getServerLocation } = require('../services/serverLocation');
const { getDomainInfo } = require('../services/domainInfo');
const { getSSLInfo } = require('../services/sslInfo');
const { getAIAnalysis } = require('../services/geminiAnalysis');

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
    const [serverLocation, domainInfo, sslInfo] = await Promise.all([
      getServerLocation(cleanDomain),
      getDomainInfo(cleanDomain),
      getSSLInfo(cleanDomain),
    ]);

    console.log(`[Analyze] Data collected. Running AI analysis...`);

    // Run Gemini AI analysis with all collected data
    const aiAnalysis = await getAIAnalysis({
      domain: cleanDomain,
      serverLocation,
      domainInfo,
      sslInfo,
    });

    console.log(`[Analyze] Complete. Trust score: ${aiAnalysis.trustScore}`);

    // Return full response
    return res.json({
      domain: cleanDomain,
      analyzedAt: new Date().toISOString(),
      serverLocation,
      domainInfo,
      sslInfo,
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
  // Reuse POST handler logic
  const cleanDomain = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();

  try {
    const [serverLocation, domainInfo, sslInfo] = await Promise.all([
      getServerLocation(cleanDomain),
      getDomainInfo(cleanDomain),
      getSSLInfo(cleanDomain),
    ]);

    const aiAnalysis = await getAIAnalysis({ domain: cleanDomain, serverLocation, domainInfo, sslInfo });

    return res.json({
      domain: cleanDomain,
      analyzedAt: new Date().toISOString(),
      serverLocation,
      domainInfo,
      sslInfo,
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

module.exports = router;
