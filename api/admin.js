const crypto = require('crypto');

const respond = (res, status, body) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');
  res.status(status).end(JSON.stringify(body));
};

const secureEqual = (a, b) => {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};

const headers = () => {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  return { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
};

function decrypt(payload) {
  const secret = process.env.PAYOUT_ENCRYPTION_KEY;
  if (!secret) throw new Error('Missing payout encryption key');
  const [ivB64, tagB64, dataB64] = String(payload).split('.');
  if (!ivB64 || !tagB64 || !dataB64) throw new Error('Invalid encrypted value');
  const key = crypto.createHash('sha256').update(secret).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return respond(res, 405, { error: 'Method not allowed' });

  const adminPassword = process.env.ADMIN_PASSWORD;
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  if (!adminPassword || !url || !serviceKey) return respond(res, 500, { error: 'Admin dashboard is not configured yet.' });

  let body = req.body || {};
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  if (!secureEqual(body.password, adminPassword)) return respond(res, 401, { error: 'Incorrect admin password.' });

  const action = String(body.action || 'list');
  const h = headers();

  try {
    if (action === 'markPaid') {
      const payoutId = String(body.payoutId || '');
      if (!/^[0-9a-f-]{36}$/i.test(payoutId)) return respond(res, 400, { error: 'Invalid payout ID.' });
      const r = await fetch(`${url}/rest/v1/winner_payouts?id=eq.${encodeURIComponent(payoutId)}`, {
        method: 'PATCH',
        headers: h,
        body: JSON.stringify({ payment_status: 'paid', paid_at: new Date().toISOString() })
      });
      if (!r.ok) throw new Error(await r.text());
      return respond(res, 200, { success: true });
    }

    if (action === 'resetTestData') {
      const payoutDelete = await fetch(`${url}/rest/v1/winner_payouts?id=not.is.null`, { method: 'DELETE', headers: h });
      if (!payoutDelete.ok) throw new Error(await payoutDelete.text());
      const entriesDelete = await fetch(`${url}/rest/v1/giveaway_entries?id=not.is.null`, { method: 'DELETE', headers: h });
      if (!entriesDelete.ok) throw new Error(await entriesDelete.text());
      const configReset = await fetch(`${url}/rest/v1/giveaway_config?id=eq.1`, {
        method: 'PATCH',
        headers: h,
        body: JSON.stringify({ winner_count: 0, is_open: true })
      });
      if (!configReset.ok) throw new Error(await configReset.text());
      return respond(res, 200, { success: true, message: 'Test data cleared. Giveaway is ready at 0/10 winners.' });
    }

    const payoutResp = await fetch(`${url}/rest/v1/winner_payouts?select=id,entry_id,account_name,bank_name,account_number_encrypted,payment_status,submitted_at,paid_at&order=submitted_at.desc`, { headers: h });
    if (!payoutResp.ok) throw new Error(await payoutResp.text());
    const payouts = await payoutResp.json();

    const entriesResp = await fetch(`${url}/rest/v1/giveaway_entries?is_winner=eq.true&select=id,claim_code,created_at,prize_claimed`, { headers: h });
    if (!entriesResp.ok) throw new Error(await entriesResp.text());
    const entries = await entriesResp.json();
    const byId = Object.fromEntries((entries || []).map(e => [e.id, e]));

    const configResp = await fetch(`${url}/rest/v1/giveaway_config?id=eq.1&select=max_winners,winner_count,is_open&limit=1`, { headers: h });
    const configs = await configResp.json();
    const config = Array.isArray(configs) ? configs[0] : null;

    const rows = (payouts || []).map(p => ({
      id: p.id,
      claimCode: byId[p.entry_id]?.claim_code || '',
      accountName: p.account_name,
      bankName: p.bank_name,
      accountNumber: decrypt(p.account_number_encrypted),
      status: p.payment_status,
      submittedAt: p.submitted_at,
      paidAt: p.paid_at
    }));

    return respond(res, 200, { payouts: rows, config });
  } catch (error) {
    console.error('admin error', error);
    return respond(res, 500, { error: 'Could not complete admin action.' });
  }
};
