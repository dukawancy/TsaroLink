// netlify/functions/explain.js
//
// Serverless function that generates a plain-English explanation of a
// phishing scan result using Google's Gemini API (free tier).
//
// This means visitors get free AI explanations without ever needing
// their own API key — your key lives only here, server-side.
//
// Free tier: 250 requests/day, 10 requests/minute (Gemini 2.0 Flash)
// Get a key at: https://aistudio.google.com
//
// Set in Netlify dashboard:
//   Site configuration → Environment variables
//     GEMINI_API_KEY = your_key

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

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        available: false,
        error: 'GEMINI_API_KEY not configured on the server.',
      }),
    };
  }

  let payload;
  try {
    payload = JSON.parse(event.body || '{}');
  } catch (e) {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Invalid JSON body.' }),
    };
  }

  const { prompt } = payload;
  if (!prompt || typeof prompt !== 'string') {
    return {
      statusCode: 400,
      headers,
      body: JSON.stringify({ error: 'Missing "prompt" field in request body.' }),
    };
  }

  try {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.4,
          maxOutputTokens: 400,
        },
      }),
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`Gemini API error: ${res.status} ${errBody}`);
    }

    const data = await res.json();
    const text =
      data.candidates?.[0]?.content?.parts?.[0]?.text ||
      'No explanation could be generated.';

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ available: true, text }),
    };
  } catch (err) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ available: false, error: err.message }),
    };
  }
};
