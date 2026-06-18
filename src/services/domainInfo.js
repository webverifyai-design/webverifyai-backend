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
      return sanitizeDomainInfo(parseRdapResponse(response.data, rootDomain));
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
    return sanitizeDomainInfo(parseRdapResponse(response.data, rootDomain));
  } catch (err) {
    const code = err.response?.status;
    if (code === 404) {
      console.warn(`[DomainInfo] rdap.org returned 404 — TLD ".${tld}" may not have RDAP support, or domain unregistered.`);
    } else {
      console.error('[DomainInfo] rdap.org Error:', err.message);
    }
  }

  // ── Attempt 3: who-dat (free, no API key, WHOIS-based fallback) ─────────────
  const fallbackResult = await getDomainInfoFallback(rootDomain);
  if (!fallbackResult.error) {
    console.log(`[DomainInfo] ✓ who-dat succeeded`);
    return sanitizeDomainInfo(fallbackResult);
  }

  // ── Attempt 4: Direct WHOIS lookup (for ccTLDs like .de, .in, etc.) ────────────
  console.log(`[DomainInfo] who-dat failed, trying direct WHOIS...`);
  const whoisResult = await getDomainInfoWhois(rootDomain);
  return sanitizeDomainInfo(whoisResult);
}

/**
 * Extract a human-readable registrar name from a registrar field that
 * may be: a plain string, or an object like
 * { name, iana, url, whoisServer, abuseEmail, abusePhone, reseller }
 * (this shape comes from who-dat / RDAP-style responses).
 */
function extractRegistrarName(registrar) {
  if (!registrar) return null;
  if (typeof registrar === 'string') return registrar.trim() || null;

  if (typeof registrar === 'object') {
    // Prefer explicit name-like fields, in order of preference
    const candidate =
      registrar.name ||
      registrar.registrarName ||
      registrar.organization ||
      registrar.reseller ||
      null;

    if (candidate && typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim();
    }

    // Last resort: IANA registrar ID is at least a meaningful string
    if (registrar.iana) return `IANA ID ${registrar.iana}`;
  }

  return null;
}

/**
 * Final safety pass — guarantees every field returned to the frontend
 * is a primitive (string/number/array of strings), never a raw object.
 * This prevents "Objects are not valid as a React child" (React error #31)
 * regardless of which upstream API path produced the data.
 */
function sanitizeDomainInfo(info) {
  if (!info || typeof info !== 'object') {
    return { error: true, registrar: '—', status: ['—'], nameservers: [] };
  }

  // Preserve error flag if it exists
  if (info.error) {
    return { error: true, domain: info.domain || 'Unknown' };
  }

  const toSafeString = (val, fallback = '—') => {
    if (val === null || val === undefined) return fallback;
    if (typeof val === 'string' || typeof val === 'number') {
      return String(val).trim() || fallback;
    }
    if (typeof val === 'object') {
      // Try registrar-style extraction first; otherwise stringify safely
      const extracted = extractRegistrarName(val);
      if (extracted) return extracted;
      return fallback;
    }
    return fallback;
  };

  const toSafeStringArray = (val) => {
    if (!val) return [];
    const arr = Array.isArray(val) ? val : [val];
    return arr
      .map(item => {
        if (typeof item === 'string') return item;
        if (typeof item === 'number') return String(item);
        if (item && typeof item === 'object') {
          return item.name || item.value || item.text || JSON.stringify(item);
        }
        return null;
      })
      .filter(Boolean);
  };

  return {
    ...info,
    domain:      toSafeString(info.domain, info.domain || '—'),
    registrar:   toSafeString(info.registrar),
    created:     toSafeString(info.created),
    updated:     toSafeString(info.updated),
    expires:     toSafeString(info.expires),
    domainAge:   toSafeString(info.domainAge),
    dnssec:      toSafeString(info.dnssec, 'Unsigned'),
    nameservers: toSafeStringArray(info.nameservers),
    status:      toSafeStringArray((info.status && info.status.length ? info.status : info.domainStatuses) || []),
  };
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
  console.log(`[DomainInfoFallback] Starting who-dat lookup for: ${rootDomain}`);
  try {
    const response = await axios.get(
      `https://who-dat.as93.net/${rootDomain}`,
      { timeout: 8000, headers: { 'Accept': 'application/json' } }
    );

    console.log(`[DomainInfoFallback] who-dat response status:`, response.status);
    const w = response.data;
    console.log(`[DomainInfoFallback] who-dat data:`, JSON.stringify(w).substring(0, 300));

    // CRITICAL: Check if domain is registered
    if (w.isRegistered === false) {
      console.log(`[DomainInfoFallback] ❌ Domain is not registered (isRegistered: false)`);
      return { error: true, domain: rootDomain };
    }

    if (!w || w.error || !w.domain) {
      console.log(`[DomainInfoFallback] ❌ who-dat returned error or empty`);
      return { error: true, domain: rootDomain };
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
      registrar: extractRegistrarName(w.registrar) || '—',
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
    console.error(`[DomainInfoFallback] who-dat error (${code || ''}):`, err.message);
    return { error: true, domain: rootDomain };
  }
}

/**
 * Attempt 4: Direct WHOIS lookup via whois-json (for ccTLDs like .de, .in, etc.)
 */
async function getDomainInfoWhois(rootDomain) {
  try {
    console.log(`[DomainInfoWhois] Starting direct WHOIS lookup for: ${rootDomain}`);
    const whois = require('whois-json');
    const result = await whois(rootDomain, { timeout: 8000 });

    console.log(`[DomainInfoWhois] WHOIS result received`);
    if (!result || result.error) {
      console.warn(`[DomainInfoWhois] WHOIS returned error or empty`);
      return { error: true, domain: rootDomain };
    }

    // Parse creation date — field names vary by registry
    const created =
      result.creationDate ||
      result.created ||
      result['registration-date'] ||
      result.registered ||
      null;

    // Parse expiry
    const expires =
      result.registryExpiryDate ||
      result.expiryDate ||
      result['registry-expiry-date'] ||
      result.expires ||
      null;

    // Parse registrar
    const registrar =
      result.registrar ||
      result['registrar-name'] ||
      result.organisation ||
      null;

    // Parse nameservers
    const nameservers = Array.isArray(result.nameServer)
      ? result.nameServer
      : result.nameServer
        ? [result.nameServer]
        : [];

    let domainAge = '—';
    if (created) {
      const years = (Date.now() - new Date(created)) / (365.25 * 24 * 3600 * 1000);
      if (!isNaN(years) && years >= 0) {
        domainAge = `${years.toFixed(1)} years`;
      }
    }

    const formatDate = (d) => {
      if (!d) return '—';
      const parsed = new Date(d);
      return isNaN(parsed.getTime()) ? '—' : parsed.toLocaleDateString('en-GB', {
        day: 'numeric', month: 'long', year: 'numeric'
      });
    };

    console.log(`[DomainInfoWhois] ✓ Successfully parsed WHOIS for ${rootDomain}`);
    return {
      domain: rootDomain,
      registrar: extractRegistrarName(registrar) || '—',
      created: formatDate(created),
      updated: '—',
      expires: formatDate(expires),
      nameservers: nameservers.map(ns => String(ns).toLowerCase().trim()).filter(Boolean),
      status: result.status ? [result.status] : ['—'],
      domainAge,
      dnssec: result.dnssec === 'yes' || result.dnssec === 'signedDelegation'
        ? 'Signed' : 'Unsigned',
      _source: 'whois-direct',
    };
  } catch (err) {
    console.warn(`[DomainInfoWhois] Direct WHOIS error: ${err.message}`);
    return { error: true, domain: rootDomain };
  }
}
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
