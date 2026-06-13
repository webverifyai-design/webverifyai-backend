const axios = require('axios');

async function getThreatIntelligence(domain) {
  try {
    const results = await Promise.allSettled([
      checkGoogleSafeBrowsing(domain),
      checkURLhaus(domain),
      checkPhishTank(domain),
      checkOpenPhish(domain),
    ]);

    return {
      googleSafeBrowsing: results[0].status === 'fulfilled' ? results[0].value : { threat: false, status: 'unknown' },
      urlhaus: results[1].status === 'fulfilled' ? results[1].value : { threat: false, status: 'unknown' },
      phishTank: results[2].status === 'fulfilled' ? results[2].value : { threat: false, status: 'unknown' },
      openPhish: results[3].status === 'fulfilled' ? results[3].value : { threat: false, status: 'unknown' },
      timestamp: new Date().toISOString(),
    };
  } catch (err) {
    console.error('[ThreatIntelligence] Error:', err.message);
    return {
      googleSafeBrowsing: { threat: false, status: 'error' },
      urlhaus: { threat: false, status: 'error' },
      phishTank: { threat: false, status: 'error' },
      openPhish: { threat: false, status: 'error' },
      timestamp: new Date().toISOString(),
      error: err.message,
    };
  }
}

async function checkGoogleSafeBrowsing(domain) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey || apiKey === 'your_google_safe_browsing_api_key_here') {
    return { threat: false, status: 'no_key', threatType: null };
  }

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'webverify-ai', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: `http://${domain}` }, { url: `https://${domain}` }],
        },
      },
      { timeout: 8000 }
    );

    if (response.data.matches && response.data.matches.length > 0) {
      const match = response.data.matches[0];
      return {
        threat: true,
        status: 'unsafe',
        threatType: match.threatType || 'UNKNOWN',
        platformType: match.platformType || 'UNKNOWN',
      };
    }

    return { threat: false, status: 'safe', threatType: null };
  } catch (err) {
    console.warn('[GoogleSafeBrowsing] Error:', err.message);
    return { threat: false, status: 'check_failed', threatType: null };
  }
}

async function checkURLhaus(domain) {
  try {
    const response = await axios.post(
      'https://urlhaus-api.abuse.ch/v1/urls/malicious/',
      new URLSearchParams({
        host: domain,
      }),
      {
        timeout: 8000,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    if (response.data.query_status === 'ok' && response.data.results && response.data.results.length > 0) {
      return {
        threat: true,
        status: 'malicious',
        urls: response.data.results.slice(0, 3).map(r => r.url),
      };
    }

    return { threat: false, status: 'clean' };
  } catch (err) {
    console.warn('[URLhaus] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

async function checkPhishTank(domain) {
  const apiKey = process.env.PHISHTANK_API_KEY;
  if (!apiKey) {
    return { threat: false, status: 'no_key' };
  }

  try {
    const response = await axios.post(
      'https://checkurl.phishtank.com/checkurl/',
      new URLSearchParams({
        url: `http://${domain}`,
        format: 'json',
        app_token: apiKey,
      }),
      {
        timeout: 8000,
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const result = response.data.results;
    if (result && result.in_database === '1') {
      return {
        threat: true,
        status: 'phishing',
        confidence: parseFloat(result.phish_confidence) || 0,
        phishId: result.phish_id,
      };
    }

    return { threat: false, status: 'clean', confidence: 0 };
  } catch (err) {
    console.warn('[PhishTank] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

async function checkOpenPhish(domain) {
  try {
    const response = await axios.get('https://openphish.com/api.txt', { timeout: 10000 });
    const urls = response.data.split('\n').filter(u => u.trim());

    const isDomainMalicious = urls.some(url => {
      try {
        const urlObj = new URL(url);
        return urlObj.hostname === domain || urlObj.hostname.endsWith(`.${domain}`);
      } catch {
        return false;
      }
    });

    return {
      threat: isDomainMalicious,
      status: isDomainMalicious ? 'phishing' : 'clean',
    };
  } catch (err) {
    console.warn('[OpenPhish] Error:', err.message);
    return { threat: false, status: 'check_failed' };
  }
}

module.exports = { getThreatIntelligence };
