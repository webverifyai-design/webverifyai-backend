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
// NOTE: 401 errors here mean the API key is restricted to other APIs
// (e.g. "Gemini API" only). Fix in Google Cloud Console:
//   APIs & Services → Credentials → [your key] → API restrictions →
//   add "Safe Browsing API" to the allowed list.
// Also confirm Safe Browsing API is ENABLED under API Library.
async function checkGoogleSafeBrowsing(domain) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey || apiKey === 'your_google_safe_browsing_api_key_here') {
    console.warn('[GoogleSafeBrowsing] No API key set — skipping');
    return { threat: false, status: 'no_key', threatType: null };
  }

  try {
    const response = await axios({
      method: 'POST',
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

    // Empty response = Google returns {} when domain is clean
    const matches = response.data?.matches;
    if (matches && matches.length > 0) {
      return {
        threat:       true,
        status:       'unsafe',
        threatType:   matches[0].threatType   || 'UNKNOWN',
        platformType: matches[0].platformType || 'UNKNOWN',
      };
    }

    return { threat: false, status: 'safe', threatType: null };

  } catch (err) {
    const code = err.response?.status;
    if (code === 401) {
      console.error('[GoogleSafeBrowsing] 401 — API key restricted. In Google Cloud Console, add "Safe Browsing API" to this key\'s API restrictions, and confirm it is enabled in API Library.');
    }
    if (code === 400) {
      console.error('[GoogleSafeBrowsing] 400 — Bad request:', JSON.stringify(err.response?.data));
    }
    console.warn('[GoogleSafeBrowsing] Error:', err.message);
    return { threat: false, status: 'check_failed', threatType: null };
  }
}

// ── 2. URLhaus (abuse.ch) ────────────────────────────────────────────────────
// As of 2024, abuse.ch requires a free "Auth-Key" for ALL requests.
// Get one free at: auth.abuse.ch
// Add to your .env / Render env vars as: URLHAUS_AUTH_KEY=your_key_here
async function checkURLhaus(domain) {
  const authKey = process.env.URLHAUS_AUTH_KEY;

  if (!authKey || authKey === 'your_urlhaus_auth_key_here') {
    console.warn('[URLhaus] No Auth-Key set — register free at auth.abuse.ch');
    return { threat: false, status: 'no_key' };
  }

  try {
    const response = await axios({
      method: 'POST',
      url: 'https://urlhaus-api.abuse.ch/v1/host/',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Auth-Key': authKey, // ← required as of abuse.ch 2024 policy change
      },
      data: new URLSearchParams({ host: domain }).toString(),
      timeout: 8000,
    });

    const data = response.data;

    // query_status: 'is_host' = found in DB, 'no_results' = clean
    if (data.query_status === 'is_host' && Array.isArray(data.urls) && data.urls.length > 0) {
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
    if (code === 401) console.error('[URLhaus] 401 — Auth-Key invalid or missing. Register free at auth.abuse.ch and check URLHAUS_AUTH_KEY env var.');
    if (code === 429) console.error('[URLhaus] 429 — Rate limited. Try again later.');
    console.warn('[URLhaus] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

// ── 3. OpenPhish ─────────────────────────────────────────────────────────────
// Free community feed — no API key required
async function checkOpenPhish(domain) {
  try {
    const response = await axios({
      method: 'GET',
      url: 'https://openphish.com/feed.txt',
      timeout: 10000,
      headers: { 'User-Agent': 'WebVerifyAI/1.0' },
      maxContentLength: 5 * 1024 * 1024, // 5MB cap — feed can be large
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
        return url.toLowerCase().includes(domainLower);
      }
    });

    return {
      threat: isFlagged,
      status: isFlagged ? 'phishing' : 'clean',
    };

  } catch (err) {
    const code = err.response?.status;
    if (code === 404) console.error('[OpenPhish] 404 — feed URL may have changed. Check openphish.com.');
    if (code === 403) console.error('[OpenPhish] 403 — Access denied, may need different User-Agent.');
    console.warn('[OpenPhish] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

module.exports = { getThreatIntelligence };
