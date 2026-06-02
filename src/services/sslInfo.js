const axios = require('axios');
const https = require('https');
const tls = require('tls');

/**
 * Fetch SSL certificate info by connecting directly to the host
 * Falls back to crt.sh for certificate transparency logs
 */
async function getSSLInfo(domain) {
  try {
    const rootDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '');

    // Try direct TLS connection first (most accurate)
    const certInfo = await getTLSCert(rootDomain);
    if (certInfo && !certInfo.error) return certInfo;

    // Fallback: crt.sh certificate transparency
    return await getCertFromCrtSh(rootDomain);

  } catch (err) {
    console.error('[SSL] Error:', err.message);
    return { error: 'Could not fetch SSL information' };
  }
}

function getTLSCert(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { servername: hostname, timeout: 8000 }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.destroy();

      if (!cert || !cert.subject) {
        return resolve({ error: 'No certificate found' });
      }

      const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
      const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
      const now = new Date();

      const daysLeft = validTo
        ? Math.floor((validTo - now) / (1000 * 60 * 60 * 24))
        : null;

      resolve({
        subject: cert.subject?.CN || hostname,
        issuer: cert.issuer?.O || cert.issuer?.CN || '—',
        issuerCN: cert.issuer?.CN || '—',
        validFrom: validFrom?.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) || '—',
        validTo: validTo?.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }) || '—',
        daysLeft,
        trusted: socket.authorized !== false,
        protocol: socket.getProtocol() || 'TLS',
        fingerprint: cert.fingerprint || '—',
        serialNumber: cert.serialNumber || '—',
        san: cert.subjectaltname
          ? cert.subjectaltname.replace(/DNS:/g, '').split(', ').slice(0, 5)
          : [],
        status: daysLeft !== null && daysLeft > 0 ? 'Valid' : 'Expired',
      });
    });

    socket.on('error', (err) => {
      resolve({ error: err.message });
    });

    socket.setTimeout(8000, () => {
      socket.destroy();
      resolve({ error: 'Connection timed out' });
    });
  });
}

async function getCertFromCrtSh(domain) {
  try {
    const response = await axios.get(
      `https://crt.sh/?q=${domain}&output=json`,
      { timeout: 10000 }
    );
    const certs = response.data;
    if (!certs || !certs.length) return { error: 'No certificates found' };

    // Get the most recent cert
    const latest = certs.sort((a, b) => new Date(b.not_before) - new Date(a.not_before))[0];

    return {
      subject: latest.common_name || domain,
      issuer: latest.issuer_name || '—',
      issuerCN: latest.issuer_name || '—',
      validFrom: new Date(latest.not_before).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }),
      validTo: new Date(latest.not_after).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' }),
      daysLeft: Math.floor((new Date(latest.not_after) - Date.now()) / (1000 * 60 * 60 * 24)),
      trusted: true,
      status: new Date(latest.not_after) > new Date() ? 'Valid' : 'Expired',
      serialNumber: latest.serial_number || '—',
      san: [],
    };
  } catch (err) {
    return { error: 'Could not fetch from crt.sh' };
  }
}

module.exports = { getSSLInfo };
