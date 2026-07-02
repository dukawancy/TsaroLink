// netlify/functions/check-url.js
//
// Serverless function that checks a URL against three real threat
// intelligence databases:
//   1. URLScan.io — URL reputation lookup, prior scan history (free, no key needed)
//   2. URLhaus    — malware URL database by abuse.ch (free, no key needed)
//   3. VirusTotal — deep scan across 70+ AV/security engines (free API key)
//
// URLScan.io and URLhaus require NO API key — completely free.
// Only VirusTotal needs a key (free tier: 500 req/day).
//
// Set in Netlify dashboard → Environment variables:
//   VIRUSTOTAL_API_KEY = your_key

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json',
  };

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

  // Hash lookup mode (File tab)
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

  // Run all three checks in parallel
  const [openPhishResult, urlhausResult, virusTotalResult] = await Promise.allSettled([
    checkURLScan(url),
    checkURLhaus(url),
    checkVirusTotal(url),
  ]);

  const response = {
    url,
    urlscan:
      openPhishResult.status === 'fulfilled'
        ? openPhishResult.value
        : { available: false, error: openPhishResult.reason?.message || 'URLScan check failed' },
    urlhaus:
      urlhausResult.status === 'fulfilled'
        ? urlhausResult.value
        : { available: false, error: urlhausResult.reason?.message || 'URLhaus check failed' },
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

// ── URLScan.io ────────────────────────────────────────────────────
// Free URL reputation lookup — no API key required for basic search.
// Docs: https://urlscan.io/docs/api/
async function checkURLScan(url) {
  try {
    // Search URLScan for existing scans of this URL/domain
    const encoded = encodeURIComponent(`page.url:"${url}"`);
    const res = await fetch(`https://urlscan.io/api/v1/search/?q=${encoded}&size=1`, {
      headers: {
        'User-Agent': 'Tsaro/1.0 phishing-detector',
        'Accept': 'application/json',
      },
    });

    if (!res.ok) {
      throw new Error(`URLScan API error: ${res.status}`);
    }

    const data = await res.json();
    const results = data.results || [];

    if (results.length === 0) {
      return {
        available: true,
        found: false,
        flagged: false,
        message: 'No prior scans found in URLScan database',
      };
    }

    const latest = results[0];
    const verdicts = latest.verdicts || {};
    const overall = verdicts.overall || {};
    const malicious = overall.malicious || false;
    const score = overall.score || 0;
    const tags = overall.tags || [];

    return {
      available: true,
      found: true,
      flagged: malicious || score > 50,
      malicious,
      score,
      tags,
      screenshotURL: latest.screenshot || null,
      scanDate: latest.task?.time || null,
    };
  } catch (e) {
    throw new Error('URLScan check failed: ' + e.message);
  }
}

// ── URLhaus ───────────────────────────────────────────────────────
// Completely free, no API key required at all.
// Docs: https://urlhaus-api.abuse.ch/
async function checkURLhaus(url) {
  const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }).toString(),
  });

  if (!res.ok) {
    throw new Error(`URLhaus API error: ${res.status}`);
  }

  const data = await res.json();

  if (data.query_status === 'no_results') {
    return {
      available: true,
      flagged: false,
      status: 'not_found',
      message: 'Not found in URLhaus malware database',
    };
  }

  const flagged = data.query_status === 'is_phishing' ||
                  data.query_status === 'is_malware' ||
                  data.url_status === 'online' ||
                  data.url_status === 'unknown';

  return {
    available: true,
    flagged: data.url_status === 'online',
    status: data.url_status || data.query_status,
    threat: data.threat || null,
    tags: data.tags || [],
    dateAdded: data.date_added || null,
  };
}

// ── VirusTotal URL check ──────────────────────────────────────────
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { available: false, error: 'VIRUSTOTAL_API_KEY not configured' };
  }

  const urlId = Buffer.from(url).toString('base64url').replace(/=+$/, '');

  const lookupRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
    method: 'GET',
    headers: { 'x-apikey': apiKey },
  });

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

// ── VirusTotal Hash Lookup ────────────────────────────────────────
async function checkVirusTotalHash(hash) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { available: false, error: 'VIRUSTOTAL_API_KEY not configured' };

  const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
    headers: { 'x-apikey': apiKey },
  });

  if (res.status === 404) {
    return {
      available: true,
      pending: false,
      notFound: true,
      message: 'This file hash has never been submitted to VirusTotal.',
    };
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
