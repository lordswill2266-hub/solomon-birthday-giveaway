const crypto = require('crypto');

const respond = (res, status, body) => {
  res.setHeader('Content-Type', 'application/json');
  res.status(status).end(JSON.stringify(body));
};

const supabaseHeaders = () => {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  return { apikey: key, Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' };
};

function encrypt(text) {
  const secret = process.env.PAYOUT_ENCRYPTION_KEY;
  if (!secret) throw new Error('PAYOUT_ENCRYPTION_KEY is missing');
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return respond(res, 405, { error: 'Method not allowed' });

  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY;
  if (!url || !serviceKey) return respond(res, 500, { error: 'Database not configured.' });

  let body = req.body || {};
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }

  const claimCode = String(body.claimCode || '').trim().toUpperCase();
  const accountName = String(body.accountName || '').trim();
  const bankName = String(body.bankName || '').trim();
  const accountNumber = String(body.accountNumber || '').replace(/\s+/g, '');

  if (!/^BDAY-[A-F0-9]{8}$/.test(claimCode)) return respond(res, 400, { error: 'Invalid claim code.' });
  if (accountName.length < 2 || bankName.length < 2 || accountNumber.length < 6 || accountNumber.length > 30) {
    return respond(res, 400, { error: 'Please enter valid payout details.' });
  }

  const headers = supabaseHeaders();
  try {
    const entryResp = await fetch(`${url}/rest/v1/giveaway_entries?claim_code=eq.${encodeURIComponent(claimCode)}&select=id,is_winner,prize_claimed&limit=1`, { headers });
    const entries = await entryResp.json();
    const entry = Array.isArray(entries) ? entries[0] : null;
    if (!entry || !entry.is_winner) return respond(res, 404, { error: 'Winner record not found.' });
    if (entry.prize_claimed) return respond(res, 409, { error: 'This prize has already been claimed.' });

    const payoutResp = await fetch(`${url}/rest/v1/winner_payouts`, {
      method: 'POST',
      headers: { ...headers, Prefer: 'return=minimal' },
      body: JSON.stringify({
        entry_id: entry.id,
        account_name: accountName,
        bank_name: bankName,
        account_number_encrypted: encrypt(accountNumber),
        payment_status: 'pending'
      })
    });

    if (!payoutResp.ok) {
      const txt = await payoutResp.text();
      if (txt.includes('duplicate') || txt.includes('unique')) return respond(res, 409, { error: 'Payout details already submitted.' });
      throw new Error(txt || 'Unable to save payout details');
    }

    const updateResp = await fetch(`${url}/rest/v1/giveaway_entries?id=eq.${entry.id}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({ prize_claimed: true })
    });
    if (!updateResp.ok) throw new Error(await updateResp.text());

    return respond(res, 200, { success: true, message: 'Payout details received.' });
  } catch (error) {
    console.error('claim error', error);
    return respond(res, 500, { error: 'Could not submit payout details. Please try again.' });
  }
};
