const axios = require('axios');

async function getContentAnalysis(domain) {
  try {
    const urls = [`https://${domain}`, `http://${domain}`];

    for (const url of urls) {
      try {
        const response = await axios.get(url, {
          timeout: 10000,
          maxRedirects: 3,
          headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          },
          validateStatus: function (status) {
            return status >= 200 && status < 500;
          },
        });

        if (response.status >= 200 && response.status < 300) {
          return analyzeContent({
            html: response.data,
            statusCode: response.status,
            contentType: response.headers['content-type'] || 'unknown',
            url: response.config.url,
            redirectCount: response.request.path.split('/').length - 2,
          });
        }
      } catch (err) {
        continue;
      }
    }

    return {
      statusCode: 0,
      contentType: 'unknown',
      suspiciousPatterns: [],
      metaTags: {},
      pageTitle: '',
      hasContactInfo: false,
      redirects: 0,
      error: 'Could not fetch content',
    };
  } catch (err) {
    console.error('[ContentAnalysis] Error:', err.message);
    return {
      statusCode: 0,
      contentType: 'unknown',
      suspiciousPatterns: [],
      metaTags: {},
      pageTitle: '',
      hasContactInfo: false,
      redirects: 0,
      error: err.message,
    };
  }
}

function analyzeContent({ html, statusCode, contentType, url, redirectCount }) {
  const suspiciousPatterns = [];
  const metaTags = {};

  if (!html || typeof html !== 'string') {
    return {
      statusCode,
      contentType,
      suspiciousPatterns,
      metaTags,
      pageTitle: '',
      hasContactInfo: false,
      redirects: redirectCount,
    };
  }

  const htmlLower = html.toLowerCase();

  // Extract title
  const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  const pageTitle = titleMatch ? titleMatch[1].trim() : '';

  // Extract meta tags
  const descMatch = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
  if (descMatch) metaTags.description = descMatch[1];

  const keywordsMatch = html.match(/<meta\s+name=["']keywords["']\s+content=["']([^"']+)["']/i);
  if (keywordsMatch) metaTags.keywords = keywordsMatch[1];

  const authorMatch = html.match(/<meta\s+name=["']author["']\s+content=["']([^"']+)["']/i);
  if (authorMatch) metaTags.author = authorMatch[1];

  // Check for suspicious patterns
  const suspiciousKeywords = [
    'bitcoin',
    'cryptocurrency',
    'crypto wallet',
    'verify account',
    'confirm identity',
    'update payment',
    'urgent action required',
    'click here immediately',
    'limited time offer',
    'act now',
    'paypal verify',
    'amazon verify',
    'bank verify',
  ];

  for (const keyword of suspiciousKeywords) {
    if (htmlLower.includes(keyword)) {
      suspiciousPatterns.push(`Contains keyword: "${keyword}"`);
    }
  }

  // Check for contact information
  const hasEmail = /[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}/i.test(html);
  const hasPhone = /(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/i.test(html);
  const hasContactForm = /<form[^>]*>([\s\S]*?)contact/i.test(html);
  const hasContactInfo = hasEmail || hasPhone || hasContactForm;

  // Check for suspicious redirects
  if (redirectCount > 2) {
    suspiciousPatterns.push(`Multiple redirects detected (${redirectCount})`);
  }

  // Check for hidden text or elements
  if (htmlLower.includes('display:none') || htmlLower.includes('visibility:hidden')) {
    suspiciousPatterns.push('Hidden HTML elements detected');
  }

  // Check for iframe injections
  const iframeCount = (html.match(/<iframe/gi) || []).length;
  if (iframeCount > 3) {
    suspiciousPatterns.push(`Multiple iframes detected (${iframeCount})`);
  }

  // Check for javascript redirects
  if (htmlLower.includes('window.location') || htmlLower.includes('document.location')) {
    suspiciousPatterns.push('JavaScript redirect detected');
  }

  return {
    statusCode,
    contentType,
    suspiciousPatterns: suspiciousPatterns.length > 0 ? suspiciousPatterns : [],
    metaTags,
    pageTitle,
    hasContactInfo,
    redirects: redirectCount,
  };
}

module.exports = { getContentAnalysis };
