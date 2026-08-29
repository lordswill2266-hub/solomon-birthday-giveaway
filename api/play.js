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
    const existingResp = await fetch(`${url}/rest/v1/giveaway_entries?device_hash=eq.${deviceHash}&select=id,is_winner,claim_code,prize_claimed&limit=1`, { headers });
    const existing = await existingResp.json();
    if (Array.isArray(existing) && existing.length) {
      const entry = existing[0];
      return json(res, 200, {
        alreadyPlayed: true,
        winner: !!entry.is_winner,
        claimCode: entry.is_winner ? entry.claim_code : null,
        claimed: !!entry.prize_claimed
      });
    }

    const configResp = await fetch(`${url}/rest/v1/giveaway_config?id=eq.1&select=max_winners,winner_count,is_open&limit=1`, { headers });
    const configs = await configResp.json();
    const config = Array.isArray(configs) ? configs[0] : null;
    if (!config || !config.is_open) return json(res, 403, { error: 'This giveaway is currently closed.' });

    const hasPrizes = Number(config.winner_count) < Number(config.max_winners);
    const winner = hasPrizes && crypto.randomInt(0, 12) === 0;
    const code = winner ? claimCode() : null;

    const insert = async (isWinner, codeValue) => fetch(`${url}/rest/v1/giveaway_entries`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'return=representation' },
      body: JSON.stringify({
        device_hash: deviceHash,
        ip_hash: ipHash,
        is_winner: isWinner,
        claim_code: codeValue
      })
    });

    let insertResp = await insert(winner, code);
    if (!insertResp.ok && winner) {
      insertResp = await insert(false, null);
    }

    if (!insertResp.ok) {
      const msg = await insertResp.text();
      if (msg.includes('duplicate') || msg.includes('unique')) {
        return json(res, 409, { error: 'This device has already used its chance.' });
      }
      throw new Error(msg || 'Unable to save giveaway entry');
    }

    const inserted = await insertResp.json();
    const actual = Array.isArray(inserted) ? inserted[0] : null;
    const actualWinner = !!actual?.is_winner;

    return json(res, 200, {
      alreadyPlayed: false,
      winner: actualWinner,
      claimCode: actualWinner ? actual.claim_code : null
    }, `birthday_played=1; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Lax`);
  } catch (error) {
    console.error('giveaway play error', error);
    return json(res, 500, { error: 'Something went wrong. Please try again.' });
  }
};
