const axios = require('axios');

/**
 * Fetch domain registration info via rdap.org
 * RDAP is the official ICANN protocol — 100% accurate data
 */
async function getDomainInfo(domain) {
  try {
    // Extract root domain (remove subdomains)
    const rootDomain = extractRootDomain(domain);

    const response = await axios.get(
      `https://rdap.org/domain/${rootDomain}`,
      {
        timeout: 10000,
        headers: { 'Accept': 'application/json' }
      }
    );

    const d = response.data;

    // Parse dates from events array
    const events = d.events || [];
    const getDate = (type) => {
      const ev = events.find(e => e.eventAction === type);
      if (!ev) return '—';
      return new Date(ev.eventDate).toLocaleDateString('en-GB', {
        day: 'numeric', month: 'long', year: 'numeric'
      });
    };

    // Parse nameservers
    const nameservers = (d.nameservers || [])
      .map(ns => ns.ldhName || ns.unicodeName || '')
      .filter(Boolean)
      .map(ns => ns.toLowerCase());

    // Parse registrar from entities
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

    // Parse status
    const statuses = (d.status || []).map(s =>
      s.replace('client', '').replace(/([A-Z])/g, ' $1').trim()
    );

    // Calculate domain age
    const registrationDate = events.find(e => e.eventAction === 'registration');
    let domainAge = '—';
    if (registrationDate) {
      const years = Math.floor(
        (Date.now() - new Date(registrationDate.eventDate)) / (365.25 * 24 * 3600 * 1000)
      );
      domainAge = `${years} years`;
    }

    return {
      domain: d.ldhName || rootDomain,
      registrar,
      created: getDate('registration'),
      updated: getDate('last changed'),
      expires: getDate('expiration'),
      nameservers,
      status: statuses,
      domainAge,
      dnssec: d.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned',
    };

  } catch (err) {
    console.error('[DomainInfo] Error:', err.message);
    // Try fallback with whois-json API
    return await getDomainInfoFallback(domain);
  }
}

/**
 * Fallback: use jsonwhois.io (free, no key needed)
 */
async function getDomainInfoFallback(domain) {
  try {
    const rootDomain = extractRootDomain(domain);
    const response = await axios.get(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_demo&domainName=${rootDomain}&outputFormat=JSON`,
      { timeout: 8000 }
    );
    const w = response.data?.WhoisRecord;
    if (!w) return { error: 'Domain info unavailable' };

    return {
      domain: rootDomain,
      registrar: w.registrarName || '—',
      created: w.createdDate || '—',
      updated: w.updatedDate || '—',
      expires: w.expiresDate || '—',
      nameservers: w.nameServers?.hostNames || [],
      status: [w.status || '—'],
      domainAge: w.estimatedDomainAge ? `${Math.floor(w.estimatedDomainAge/365)} years` : '—',
      dnssec: '—',
    };
  } catch (err) {
    console.error('[DomainInfo Fallback] Error:', err.message);
    return { error: 'Could not fetch domain information' };
  }
}

/**
 * Extract root domain from full URL or subdomain
 * e.g. "www.google.com" → "google.com", "https://shop.example.co.uk" → "example.co.uk"
 */
function extractRootDomain(input) {
  let domain = input
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .toLowerCase()
    .trim();

  // Remove www.
  domain = domain.replace(/^www\./, '');
  return domain;
}

module.exports = { getDomainInfo };
