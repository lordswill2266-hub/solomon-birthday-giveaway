const crypto = require('crypto');

const json = (res, status, body, cookie) => {
  if (cookie) res.setHeader('Set-Cookie', cookie);
  res.setHeader('Content-Type', 'application/json');
  res.status(status).end(JSON.stringify(body));
};

const baseHeaders = () => {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  return {
    apikey: key,
    Authorization: `Bearer ${key}`,
    'Content-Type': 'application/json'
  };
};

const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const claimCode = () => `BDAY-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' });

  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  if (!url || !serviceKey) return json(res, 500, { error: 'Giveaway database is not configured yet.' });

  let body = req.body || {};
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const deviceToken = String(body.deviceToken || '').trim();
  const fingerprint = String(body.fingerprint || '').slice(0, 1000);
  if (deviceToken.length < 20) return json(res, 400, { error: 'Invalid device token.' });

  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = forwarded || req.socket?.remoteAddress || 'unknown';
  const ua = String(req.headers['user-agent'] || 'unknown');
  const deviceHash = hash(`${deviceToken}|${fingerprint}|${ua}`);
  const ipHash = hash(ip);
  const headers = baseHeaders();

  try {
    const configResp = await fetch(`${url}/rest/v1/giveaway_config?id=eq.1&select=max_winners,winner_count,is_open&limit=1`, { headers });
    const configs = await configResp.json();
    const config = Array.isArray(configs) ? configs[0] : null;
    if (!config || !config.is_open) return json(res, 403, { error: 'This giveaway is currently closed.' });

    const existingResp = await fetch(`${url}/rest/v1/giveaway_entries?device_hash=eq.${deviceHash}&select=id,is_winner,claim_code,prize_claimed&limit=1`, { headers });
    const existing = await existingResp.json();

    if (Array.isArray(existing) && existing.length) {
      let entry = existing[0];

      // TRIAL MODE: upgrade an earlier losing test entry to a winner if a prize slot is available.
      if (!entry.is_winner && Number(config.winner_count) < Number(config.max_winners)) {
        const code = claimCode();
        const patchResp = await fetch(`${url}/rest/v1/giveaway_entries?id=eq.${entry.id}`, {
          method: 'PATCH',
          headers: { ...headers, Prefer: 'return=representation' },
          body: JSON.stringify({ is_winner: true, claim_code: code })
        });
        if (patchResp.ok) {
          const patched = await patchResp.json();
          if (Array.isArray(patched) && patched[0]) entry = patched[0];
        }
      }

      return json(res, 200, {
        alreadyPlayed: false,
        winner: !!entry.is_winner,
        claimCode: entry.is_winner ? entry.claim_code : null,
        claimed: !!entry.prize_claimed,
        trialMode: true
      });
    }

    const hasPrizes = Number(config.winner_count) < Number(config.max_winners);
    const winner = hasPrizes;
    const code = winner ? claimCode() : null;

    const insertResp = await fetch(`${url}/rest/v1/giveaway_entries`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'return=representation' },
      body: JSON.stringify({ device_hash: deviceHash, ip_hash: ipHash, is_winner: winner, claim_code: code })
    });

    if (!insertResp.ok) throw new Error(await insertResp.text());

    const inserted = await insertResp.json();
    const actual = Array.isArray(inserted) ? inserted[0] : null;

    return json(res, 200, {
      alreadyPlayed: false,
      winner: !!actual?.is_winner,
      claimCode: actual?.is_winner ? actual.claim_code : null,
      trialMode: true
    }, `birthday_played=1; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`);
  } catch (error) {
    console.error('giveaway play error', error);
    return json(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
