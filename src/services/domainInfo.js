const axios = require('axios');

// ── In-memory cache for IANA RDAP bootstrap (refreshed every 24h) ────────────
let rdapBootstrapCache = null;
let rdapBootstrapFetchedAt = 0;
const BOOTSTRAP_TTL = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Fetch IANA's official RDAP bootstrap registry — tells us which RDAP
 * server is authoritative for each TLD. This is the source rdap.org
 * itself uses, but querying it directly avoids rdap.org's own outages/404s.
 * https://data.iana.org/rdap/dns.json
 */
async function getRdapServerForTld(tld) {
  const now = Date.now();

  if (!rdapBootstrapCache || (now - rdapBootstrapFetchedAt) > BOOTSTRAP_TTL) {
    try {
      const res = await axios.get('https://data.iana.org/rdap/dns.json', { timeout: 8000 });
      rdapBootstrapCache = res.data;
      rdapBootstrapFetchedAt = now;
    } catch (err) {
      console.warn('[DomainInfo] Could not fetch IANA RDAP bootstrap:', err.message);
      return null;
    }
  }

  const services = rdapBootstrapCache?.services || [];
  for (const [tlds, urls] of services) {
    if (tlds.includes(tld)) {
      // Prefer https URL
      const httpsUrl = urls.find(u => u.startsWith('https://')) || urls[0];
      return httpsUrl.endsWith('/') ? httpsUrl : httpsUrl + '/';
    }
  }
  return null;
}

/**
 * Fetch domain registration info via RDAP (official ICANN protocol)
 */
async function getDomainInfo(domain) {
  const rootDomain = extractRootDomain(domain);
  const tld = rootDomain.split('.').pop();

  // ── Attempt 1: Query the correct RDAP server directly (via IANA bootstrap) ──
  try {
    const rdapServer = await getRdapServerForTld(tld);
    if (rdapServer) {
      const url = `${rdapServer}domain/${rootDomain}`;
      console.log(`[DomainInfo] Querying RDAP: ${url}`);
      const response = await axios.get(url, {
        timeout: 10000,
        headers: { 'Accept': 'application/rdap+json, application/json' },
      });
      return parseRdapResponse(response.data, rootDomain);
    }
  } catch (err) {
    const code = err.response?.status;
    console.warn(`[DomainInfo] Direct RDAP lookup failed (${code || err.message}). Trying rdap.org...`);
  }

  // ── Attempt 2: rdap.org as a generic bootstrap fallback ─────────────────────
  try {
    const response = await axios.get(`https://rdap.org/domain/${rootDomain}`, {
      timeout: 10000,
      headers: { 'Accept': 'application/rdap+json, application/json' },
    });
    return parseRdapResponse(response.data, rootDomain);
  } catch (err) {
    const code = err.response?.status;
    if (code === 404) {
      console.warn(`[DomainInfo] rdap.org returned 404 — TLD ".${tld}" may not have RDAP support, or domain unregistered.`);
    } else {
      console.error('[DomainInfo] rdap.org Error:', err.message);
    }
  }

  // ── Attempt 3: who-dat (free, no API key, WHOIS-based fallback) ─────────────
  return await getDomainInfoFallback(rootDomain);
}

/**
 * Parse a standard RDAP JSON response into our normalized shape
 */
function parseRdapResponse(d, rootDomain) {
  const events = d.events || [];

  const getDate = (type) => {
    const ev = events.find(e => e.eventAction === type);
    if (!ev) return '—';
    return new Date(ev.eventDate).toLocaleDateString('en-GB', {
      day: 'numeric', month: 'long', year: 'numeric',
    });
  };

  const nameservers = (d.nameservers || [])
    .map(ns => ns.ldhName || ns.unicodeName || '')
    .filter(Boolean)
    .map(ns => ns.toLowerCase());

  const entities = d.entities || [];
  let registrar = '—';
  for (const entity of entities) {
    if (entity.roles && entity.roles.includes('registrar')) {
      registrar = entity.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3]
        || entity.publicIds?.[0]?.identifier
        || '—';
      break;
    }
  }

  const statuses = (d.status || []).map(s =>
    s.replace('client', '').replace(/([A-Z])/g, ' $1').trim()
  );

  const registrationEvent = events.find(e => e.eventAction === 'registration');
  let domainAge = '—';
  if (registrationEvent) {
    const years = (Date.now() - new Date(registrationEvent.eventDate)) / (365.25 * 24 * 3600 * 1000);
    domainAge = `${years.toFixed(1)} years`;
  }

  return {
    domain: d.ldhName?.toLowerCase() || rootDomain,
    registrar,
    created: getDate('registration'),
    updated: getDate('last changed'),
    expires: getDate('expiration'),
    nameservers,
    status: statuses.length ? statuses : ['—'],
    domainAge,
    dnssec: d.secureDNS?.delegationSigned === true ? 'Signed' : 'Unsigned',
  };
}

/**
 * Fallback: who-dat — free, open-source WHOIS API, no key required
 * https://github.com/Lissy93/who-dat (public hosted instance)
 */
async function getDomainInfoFallback(rootDomain) {
  try {
    const response = await axios.get(
      `https://who-dat.as93.net/${rootDomain}`,
      { timeout: 8000, headers: { 'Accept': 'application/json' } }
    );

    const w = response.data;
    if (!w || w.error) {
      return { error: 'Domain information unavailable from all sources' };
    }

    // who-dat response shape: { domain, registrar: { name }, dates: { created, updated, expiry }, nameServers: [], status: [] }
    const created = w.dates?.created || w.creation_date || null;
    let domainAge = '—';
    if (created) {
      const years = (Date.now() - new Date(created)) / (365.25 * 24 * 3600 * 1000);
      if (!isNaN(years)) domainAge = `${years.toFixed(1)} years`;
    }

    const formatDate = (dateStr) => {
      if (!dateStr) return '—';
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '—';
      return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    };

    return {
      domain: w.domain || rootDomain,
      registrar: w.registrar?.name || w.registrar || '—',
      created: formatDate(w.dates?.created || w.creation_date),
      updated: formatDate(w.dates?.updated || w.updated_date),
      expires: formatDate(w.dates?.expiry || w.expiration_date),
      nameservers: (w.nameServers || w.name_servers || []).map(ns => String(ns).toLowerCase()),
      status: (Array.isArray(w.status) ? w.status : [w.status]).filter(Boolean).map(s =>
        String(s).replace('client', '').replace(/([A-Z])/g, ' $1').trim()
      ),
      domainAge,
      dnssec: w.dnssec === true || w.dnssec === 'signed' ? 'Signed' : 'Unsigned',
      _source: 'who-dat-fallback',
    };
  } catch (err) {
    const code = err.response?.status;
    console.error(`[DomainInfo Fallback] who-dat error (${code || ''}):`, err.message);
    return {
      error: 'Could not fetch domain information from any source',
      domain: rootDomain,
      registrar: '—',
      created: '—',
      updated: '—',
      expires: '—',
      nameservers: [],
      status: ['—'],
      domainAge: '—',
      dnssec: '—',
    };
  }
}

/**
 * Extract root domain from full URL or subdomain
 * e.g. "www.google.com" -> "google.com", "https://shop.example.co.uk" -> "example.co.uk"
 */
function extractRootDomain(input) {
  let domain = input
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .toLowerCase()
    .trim();

  domain = domain.replace(/^www\./, '');

  // Handle multi-part TLDs (co.uk, com.au, etc.) — best-effort
  const multiPartTlds = ['co.uk', 'com.au', 'co.in', 'co.jp', 'com.br', 'org.uk', 'net.in', 'co.nz'];
  const parts = domain.split('.');

  if (parts.length > 2) {
    const lastTwo = parts.slice(-2).join('.');
    if (multiPartTlds.includes(lastTwo)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  return domain;
}

module.exports = { getDomainInfo };
