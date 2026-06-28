// netlify/functions/check-url.js
//
// Serverless function that checks a URL against two real threat
// intelligence databases:
//   1. Google Safe Browsing  (fast, binary "is this known-bad" check)
//   2. VirusTotal            (deep scan across 70+ AV/security engines)
//
// API keys are read from Netlify environment variables and are NEVER
// exposed to the browser. Set these in Netlify dashboard:
//   Site settings → Environment variables
//     GOOGLE_SAFE_BROWSING_KEY = your_key
//     VIRUSTOTAL_API_KEY       = your_key

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: 'Method not allowed. Use POST.' }),
    };
  }

  let url, hash, hashType;
  try {
    const body = JSON.parse(event.body || '{}');
    url      = body.url;
    hash     = body.hash;
    hashType = body.type;
  } catch (e) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON body.' }),
    };
  }

  // Hash lookup mode
  if (hash && !url) {
    const vtResult = await checkVirusTotalHash(hash).catch(e => ({
      available: false, error: e.message
    }));
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ hash, type: hashType, virusTotal: vtResult }),
    };
  }

  if (!url || typeof url !== 'string') {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Missing "url" or "hash" field in request body.' }),
    };
  }

  // Run both checks in parallel — if a key is missing, that check is skipped gracefully
  const [safeBrowsingResult, virusTotalResult] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkVirusTotal(url),
  ]);

  const response = {
    url,
    safeBrowsing:
      safeBrowsingResult.status === 'fulfilled'
        ? safeBrowsingResult.value
        : { available: false, error: safeBrowsingResult.reason?.message || 'Safe Browsing check failed' },
    virusTotal:
      virusTotalResult.status === 'fulfilled'
        ? virusTotalResult.value
        : { available: false, error: virusTotalResult.reason?.message || 'VirusTotal check failed' },
  };

  return {
    statusCode: 200,
    headers,
    body: JSON.stringify(response),
  };
};

// ── VirusTotal Hash Lookup ───────────────────────────────────────
async function checkVirusTotalHash(hash) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { available: false, error: 'VIRUSTOTAL_API_KEY not configured' };

  const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { 'x-apikey': apiKey },
  });

  if (res.status === 404) {
    return { available: true, pending: false, notFound: true,
             message: 'This file hash has never been submitted to VirusTotal.' };
  }
  if (!res.ok) throw new Error(`VirusTotal API error: ${res.status}`);

  const data  = await res.json();
  const stats = data.data?.attributes?.last_analysis_stats || {};
  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const harmless   = stats.harmless   || 0;
  const undetected = stats.undetected || 0;
  const totalEngines = malicious + suspicious + harmless + undetected;

  return {
    available: true,
    pending: false,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalEngines,
    flagged: malicious > 0 || suspicious > 0,
    reputation: data.data?.attributes?.reputation ?? null,
  };
}

// ── Google Safe Browsing ──────────────────────────────────────────
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) {
    return { available: false, error: 'GOOGLE_SAFE_BROWSING_KEY not configured' };
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`;

  const payload = {
    client: { clientId: 'phishing-url-detector', clientVersion: '1.0.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errBody = await res.text();
    throw new Error(`Safe Browsing API error: ${res.status} ${errBody}`);
  }

  const data = await res.json();
  const matches = data.matches || [];

  return {
    available: true,
    flagged: matches.length > 0,
    threatTypes: matches.map((m) => m.threatType),
  };
}

// ── VirusTotal ───────────────────────────────────────────────────
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { available: false, error: 'VIRUSTOTAL_API_KEY not configured' };
  }

  // VirusTotal v3 requires the URL to be submitted, then queried by its ID
  // The ID is the base64 (url-safe, no padding) encoding of the URL
  const urlId = Buffer.from(url).toString('base64url').replace(/=+$/, '');

  const lookupRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
    method: 'GET',
    headers: { 'x-apikey': apiKey },
  });

  // If VT has never seen this URL before, submit it for a fresh scan
  if (lookupRes.status === 404) {
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!submitRes.ok) {
      throw new Error(`VirusTotal submit error: ${submitRes.status}`);
    }

    // Freshly submitted URLs take time to analyze — report as pending
    return {
      available: true,
      pending: true,
      message: 'URL submitted for first-time analysis. Check again in ~60 seconds for full results.',
    };
  }

  if (!lookupRes.ok) {
    const errBody = await lookupRes.text();
    throw new Error(`VirusTotal API error: ${lookupRes.status} ${errBody}`);
  }

  const data = await lookupRes.json();
  const stats = data.data?.attributes?.last_analysis_stats || {};
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const totalEngines = malicious + suspicious + harmless + undetected;

  return {
    available: true,
    pending: false,
    malicious,
    suspicious,
    harmless,
    undetected,
    totalEngines,
    flagged: malicious > 0 || suspicious > 0,
    reputation: data.data?.attributes?.reputation ?? null,
  };
}
