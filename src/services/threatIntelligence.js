const axios = require('axios');

async function getThreatIntelligence(domain) {
  try {
    const results = await Promise.allSettled([
      checkGoogleSafeBrowsing(domain),
      checkURLhaus(domain),
      checkOpenPhish(domain),
    ]);

    return {
      googleSafeBrowsing: results[0].status === 'fulfilled' ? results[0].value : { threat: false, status: 'unknown' },
      urlhaus:            results[1].status === 'fulfilled' ? results[1].value : { threat: false, status: 'unknown' },
      openPhish:          results[2].status === 'fulfilled' ? results[2].value : { threat: false, status: 'unknown' },
      // PhishTank removed — site abandoned, registration broken
      timestamp: new Date().toISOString(),
    };
  } catch (err) {
    console.error('[ThreatIntelligence] Error:', err.message);
    return {
      googleSafeBrowsing: { threat: false, status: 'error' },
      urlhaus:            { threat: false, status: 'error' },
      openPhish:          { threat: false, status: 'error' },
      timestamp: new Date().toISOString(),
      error: err.message,
    };
  }
}

// ── 1. Google Safe Browsing ───────────────────────────────────────────────────
// FIX: key must be passed as query param AND request body format was slightly wrong
async function checkGoogleSafeBrowsing(domain) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey === 'your_google_safe_browsing_api_key_here') {
    console.warn('[GoogleSafeBrowsing] No API key set — skipping');
    return { threat: false, status: 'no_key', threatType: null };
  }

  try {
    const response = await axios({
      method: 'POST',
      // FIX: correct v4 endpoint with key as query param
      url: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      headers: { 'Content-Type': 'application/json' },
      timeout: 8000,
      data: {
        client: {
          clientId:      'webverify-ai',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes:      ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes:    ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [
            { url: `http://${domain}/` },
            { url: `https://${domain}/` },
          ],
        },
      },
    });

    // Empty response body = no threats found (Google returns {} when clean)
    const matches = response.data?.matches;
    if (matches && matches.length > 0) {
      return {
        threat:       true,
        status:       'unsafe',
        threatType:   matches[0].threatType    || 'UNKNOWN',
        platformType: matches[0].platformType  || 'UNKNOWN',
      };
    }

    return { threat: false, status: 'safe', threatType: null };

  } catch (err) {
    // 401 = bad key, 400 = bad request format
    const code = err.response?.status;
    if (code === 401) console.error('[GoogleSafeBrowsing] 401 — API key is invalid or Safe Browsing API not enabled in Google Cloud Console');
    if (code === 400) console.error('[GoogleSafeBrowsing] 400 — Bad request format:', err.response?.data);
    console.warn('[GoogleSafeBrowsing] Error:', err.message);
    return { threat: false, status: 'check_failed', threatType: null };
  }
}

// ── 2. URLhaus (abuse.ch) ────────────────────────────────────────────────────
// FIX: correct endpoint is /v1/host/ not /v1/urls/malicious/
// No API key needed — completely free
async function checkURLhaus(domain) {
  try {
    const response = await axios({
      method: 'POST',
      url: 'https://urlhaus-api.abuse.ch/v1/host/',   // ← FIXED endpoint
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      // FIX: param is 'host' not 'url'
      data: new URLSearchParams({ host: domain }).toString(),
      timeout: 8000,
    });

    const data = response.data;

    // query_status: 'is_host' = found, 'no_results' = clean
    if (data.query_status === 'is_host' && data.urls && data.urls.length > 0) {
      const maliciousUrls = data.urls.filter(u => u.url_status === 'online');
      if (maliciousUrls.length > 0) {
        return {
          threat:  true,
          status:  'malicious',
          count:   maliciousUrls.length,
          samples: maliciousUrls.slice(0, 2).map(u => u.url),
        };
      }
    }

    return { threat: false, status: 'clean' };

  } catch (err) {
    const code = err.response?.status;
    if (code === 401) console.error('[URLhaus] 401 — This endpoint requires no key. Check if IP is blocked.');
    if (code === 429) console.error('[URLhaus] 429 — Rate limited. Try again later.');
    console.warn('[URLhaus] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

// ── 3. OpenPhish ─────────────────────────────────────────────────────────────
// FIX: correct URL is /feed.txt not /api.txt
// No API key needed — free community feed
async function checkOpenPhish(domain) {
  try {
    const response = await axios({
      method: 'GET',
      url: 'https://openphish.com/feed.txt',    // ← FIXED: was /api.txt (404)
      timeout: 10000,
      headers: { 'User-Agent': 'WebVerifyAI/1.0' },
      // feed.txt can be large — limit response size
      maxContentLength: 5 * 1024 * 1024, // 5MB cap
    });

    const lines = response.data
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);

    const domainLower = domain.toLowerCase();

    const isFlagged = lines.some(url => {
      try {
        const parsed = new URL(url);
        return (
          parsed.hostname === domainLower ||
          parsed.hostname.endsWith(`.${domainLower}`)
        );
      } catch {
        // fallback plain string match if URL parse fails
        return url.toLowerCase().includes(domainLower);
      }
    });

    return {
      threat: isFlagged,
      status: isFlagged ? 'phishing' : 'clean',
    };

  } catch (err) {
    const code = err.response?.status;
    if (code === 404) console.error('[OpenPhish] 404 — feed.txt URL has changed. Check openphish.com for updated feed URL.');
    if (code === 403) console.error('[OpenPhish] 403 — Access denied. OpenPhish may require User-Agent header.');
    console.warn('[OpenPhish] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

module.exports = { getThreatIntelligence };
