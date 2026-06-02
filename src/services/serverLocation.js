const axios = require('axios');
const dns = require('dns').promises;

/**
 * Resolve domain to IP, then fetch location from ip-api.com
 * ip-api.com is free, no key needed, very accurate
 */
async function getServerLocation(domain) {
  try {
    // Step 1: Resolve domain → IP
    let ip = null;
    try {
      const addresses = await dns.resolve4(domain);
      ip = addresses[0];
    } catch {
      // Fallback: let ip-api resolve by domain directly
      ip = domain;
    }

    // Step 2: Fetch location data from ip-api.com
    const response = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`,
      { timeout: 8000 }
    );

    const d = response.data;

    if (d.status === 'fail') {
      return { error: d.message || 'Location lookup failed', ip };
    }

    return {
      ip: d.query,
      city: d.city || '—',
      region: d.regionName || '—',
      country: d.country || '—',
      countryCode: d.countryCode || '—',
      timezone: d.timezone || '—',
      isp: d.isp || '—',
      org: d.org || '—',
      asn: d.as || '—',
      lat: d.lat,
      lon: d.lon,
    };
  } catch (err) {
    console.error('[ServerLocation] Error:', err.message);
    return { error: 'Could not fetch server location' };
  }
}

module.exports = { getServerLocation };
