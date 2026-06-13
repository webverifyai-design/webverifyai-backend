const dns = require('dns').promises;

async function getDNSSecurityCheck(domain) {
  try {
    const rootDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    const results = await Promise.allSettled([
      checkDNSSEC(rootDomain),
      checkMXRecords(rootDomain),
      checkSPFRecord(rootDomain),
      checkTLSARecords(rootDomain),
    ]);

    return {
      dnssec: results[0].status === 'fulfilled' ? results[0].value : { status: 'unknown', signed: false },
      mxRecords: results[1].status === 'fulfilled' ? results[1].value : { exists: false, count: 0, records: [], quality: 'unknown' },
      spfRecord: results[2].status === 'fulfilled' ? results[2].value : { exists: false, valid: false, record: null },
      tlsaRecords: results[3].status === 'fulfilled' ? results[3].value : { exists: false, records: [] },
      timestamp: new Date().toISOString(),
    };
  } catch (err) {
    console.error('[DNSSecurity] Error:', err.message);
    return {
      dnssec: { status: 'error', signed: false },
      mxRecords: { exists: false, count: 0, records: [], quality: 'unknown' },
      spfRecord: { exists: false, valid: false, record: null },
      tlsaRecords: { exists: false, records: [] },
      timestamp: new Date().toISOString(),
      error: err.message,
    };
  }
}

async function checkDNSSEC(domain) {
  try {
    const dnssecRecords = await dns.resolveSoa(domain);
    if (dnssecRecords) {
      return { status: 'enabled', signed: true };
    }
    return { status: 'disabled', signed: false };
  } catch (err) {
    console.warn('[DNSSEC] Check failed:', err.message);
    return { status: 'unknown', signed: false };
  }
}

async function checkMXRecords(domain) {
  try {
    const mxRecords = await dns.resolveMx(domain);

    if (!mxRecords || mxRecords.length === 0) {
      return { exists: false, count: 0, records: [], quality: 'poor' };
    }

    const records = mxRecords
      .sort((a, b) => a.priority - b.priority)
      .slice(0, 5)
      .map(r => ({ priority: r.priority, exchange: r.exchange }));

    const quality = mxRecords.length >= 2 ? 'good' : 'fair';

    return {
      exists: true,
      count: mxRecords.length,
      records,
      quality,
    };
  } catch (err) {
    console.warn('[MXRecords] Check failed:', err.message);
    return { exists: false, count: 0, records: [], quality: 'unknown' };
  }
}

async function checkSPFRecord(domain) {
  try {
    const txtRecords = await dns.resolveTxt(domain);

    if (!txtRecords || txtRecords.length === 0) {
      return { exists: false, valid: false, record: null };
    }

    let spfRecord = null;
    for (const record of txtRecords) {
      const recordStr = record.join('');
      if (recordStr.startsWith('v=spf1')) {
        spfRecord = recordStr;
        break;
      }
    }

    if (!spfRecord) {
      return { exists: false, valid: false, record: null };
    }

    const isValid = validateSPFRecord(spfRecord);

    return {
      exists: true,
      valid: isValid,
      record: spfRecord.substring(0, 100),
    };
  } catch (err) {
    console.warn('[SPFRecord] Check failed:', err.message);
    return { exists: false, valid: false, record: null };
  }
}

async function checkTLSARecords(domain) {
  try {
    const tlsaRecords = await dns.resolveTlsa(domain);

    if (!tlsaRecords || tlsaRecords.length === 0) {
      return { exists: false, records: [] };
    }

    const records = tlsaRecords.slice(0, 3).map(r => ({
      usage: r.usage,
      selector: r.selector,
      digestType: r.digestType,
    }));

    return {
      exists: true,
      records,
    };
  } catch (err) {
    console.warn('[TLSARecords] Not available or check failed:', err.message);
    return { exists: false, records: [] };
  }
}

function validateSPFRecord(spf) {
  if (!spf.startsWith('v=spf1')) {
    return false;
  }

  const mechanisms = ['ip4:', 'ip6:', 'a', 'mx', 'ptr', 'exists:', 'include:', 'redirect='];
  const hasValidMechanisms = mechanisms.some(mech => spf.includes(mech));

  const hasQualifier = spf.includes('~all') || spf.includes('-all');

  return hasValidMechanisms && hasQualifier;
}

module.exports = { getDNSSecurityCheck };
