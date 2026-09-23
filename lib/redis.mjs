// Server-only storage. Configure UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN on Vercel.
export async function redis(...command) {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token || !url.startsWith('https://')) throw Error('storage is not configured');
  const response = await fetch(url, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(command), cache: 'no-store',
  });
  if (!response.ok) throw Error('storage request failed');
  const data = await response.json();
  if (data.error) throw Error('storage command failed');
  return data.result;
}

export const k = {
  account: handle => `p8:account:${handle}`,
  accountName: id => `p8:account-name:${id}`,
  key: id => `p8:key:${id}`,
  keys: id => `p8:keys:${id}`,
  notes: id => `p8:notes:${id}`,
  challenge: id => `p8:challenge:${id}`,
  session: hash => `p8:session:${hash}`,
  attempts: handle => `p8:attempts:${handle}`,
};

const claim = `
local account = redis.call('GET', KEYS[1])
if ARGV[1] == 'new' then
  if account or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
  redis.call('SET', KEYS[1], ARGV[2])
  redis.call('SET', KEYS[4], ARGV[3])
  redis.call('SET', KEYS[5], ARGV[9])
else
  if account ~= ARGV[2] or redis.call('EXISTS', KEYS[2]) == 1 then return 0 end
end
redis.call('HSET', KEYS[2], 'account', ARGV[2], 'name', ARGV[4], 'created', ARGV[5], 'public', ARGV[6], 'counter', ARGV[7])
redis.call('SADD', KEYS[3], ARGV[8])
return 1
`;

export async function savePasskey({ mode, accountId, handle, credential, name, notes }) {
  return redis('EVAL', claim, 5, k.account(handle), k.key(credential.id),
    k.keys(accountId), k.accountName(accountId), k.notes(accountId), mode, accountId, handle,
    name, new Date().toISOString(), JSON.stringify(credential.publicKey), String(credential.counter),
    credential.id, JSON.stringify(notes));
}

export async function getPasskey(id) {
  const fields = await redis('HGETALL', k.key(id));
  if (!fields || (Array.isArray(fields) ? fields.length === 0 : Object.keys(fields).length === 0)) return null;
  return Object.fromEntries(Array.isArray(fields) ? Array.from({ length: fields.length / 2 }, (_, i) => [fields[2 * i], fields[2 * i + 1]]) : Object.entries(fields));
}

export async function getPasskeys(accountId) {
  const ids = await redis('SMEMBERS', k.keys(accountId)) || [];
  const keys = await Promise.all(ids.map(async id => ({ id, ...await getPasskey(id) })));
  return keys.filter(x => x.account).sort((a, b) => a.created.localeCompare(b.created));
}

const deleteOwned = `
if redis.call('HGET', KEYS[1], 'account') ~= ARGV[1] then return -1 end
if redis.call('SCARD', KEYS[2]) <= 1 then return 0 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 1
`;
export async function deletePasskey(accountId, credentialId) {
  return redis('EVAL', deleteOwned, 2, k.key(credentialId), k.keys(accountId), accountId, credentialId);
}

const updateCounter = `
if redis.call('HGET', KEYS[1], 'account') ~= ARGV[1] then return 0 end
local before = tonumber(redis.call('HGET', KEYS[1], 'counter'))
if before ~= tonumber(ARGV[2]) then return 0 end
local after = tonumber(ARGV[3])
if after ~= 0 and after <= before then return 0 end
redis.call('HSET', KEYS[1], 'counter', ARGV[3])
return 1
`;
export async function saveCounter(id, accountId, before, after) {
  return redis('EVAL', updateCounter, 1, k.key(id), accountId, String(before), String(after));
}
