// netlify/functions/explain.js
//
// Serverless function that generates a plain-English explanation of a
// phishing scan result using Groq's free API (Llama 3.3 70B).
//
// This means visitors get free AI explanations without ever needing
// their own API key — your key lives only here, server-side.
//
// Free tier: genuinely free, no billing card required.
// Get a key at: https://console.groq.com -> API Keys
//
// Set in Netlify dashboard:
//   Site configuration -> Environment variables
//     GROQ_API_KEY = your_key

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

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        available: false,
        error: 'GROQ_API_KEY not configured on the server.',
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
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.4,
        max_tokens: 400,
      }),
    });

    if (!res.ok) {
      const errBody = await res.text();
      throw new Error(`Groq API error: ${res.status} ${errBody}`);
    }

    const data = await res.json();
    const text = data.choices?.[0]?.message?.content || 'No explanation could be generated.';

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
