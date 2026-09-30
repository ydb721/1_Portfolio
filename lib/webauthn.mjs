import { createHash, createPublicKey, verify as verifySignature, timingSafeEqual } from 'node:crypto';

export const b64 = bytes => Buffer.from(bytes).toString('base64url');
export const unb64 = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('invalid base64url');
  return Buffer.from(value, 'base64url');
};
const same = (a, b) => a.length === b.length && timingSafeEqual(a, b);

// Bounded, definite-length CBOR reader for WebAuthn attestation and COSE EC2 keys.
export function readCBOR(bytes, offset = 0, depth = 0) {
  if (depth > 12 || offset >= bytes.length) throw Error('invalid CBOR');
  const initial = bytes[offset++], major = initial >> 5, ai = initial & 31;
  let length;
  if (ai < 24) length = ai;
  else if (ai === 24) length = bytes[offset++];
  else if (ai === 25) { length = bytes.readUInt16BE(offset); offset += 2; }
  else if (ai === 26) { length = bytes.readUInt32BE(offset); offset += 4; }
  else throw Error('unsupported CBOR length');
  if (!Number.isSafeInteger(length) || length > 1_000_000) throw Error('CBOR too large');
  if (major === 0 || major === 1) return [major === 0 ? length : -1 - length, offset];
  if (major === 2 || major === 3) {
    if (offset + length > bytes.length) throw Error('truncated CBOR');
    const value = bytes.subarray(offset, offset + length);
    return [major === 2 ? value : value.toString('utf8'), offset + length];
  }
  if (major === 4 || major === 5) {
    const result = major === 4 ? [] : new Map();
    for (let i = 0; i < length; i++) {
      const [key, next] = readCBOR(bytes, offset, depth + 1); offset = next;
      if (major === 4) result.push(key);
      else {
        const [value, end] = readCBOR(bytes, offset, depth + 1); offset = end;
        if (result.has(key)) throw Error('duplicate CBOR key');
        result.set(key, value);
      }
    }
    return [result, offset];
  }
  throw Error('unsupported CBOR type');
}

function checkClient(clientDataJSON, expectedType, challenge, origin) {
  const raw = unb64(clientDataJSON);
  if (raw.length > 8192) throw Error('client data too large');
  const data = JSON.parse(raw.toString('utf8'));
  if (data.type !== expectedType || data.origin !== origin || data.crossOrigin === true ||
      !same(unb64(data.challenge), unb64(challenge))) throw Error('client data mismatch');
  return raw;
}
function checkAuthenticator(data, rpId, requireAttested = false) {
  if (data.length < 37 || data.length > 16384 ||
      !same(data.subarray(0, 32), createHash('sha256').update(rpId).digest())) throw Error('RP mismatch');
  const flags = data[32];
  if (!(flags & 1) || !(flags & 4) || (requireAttested && !(flags & 64))) throw Error('user verification required');
  return { flags, counter: data.readUInt32BE(33) };
}
export function verifyRegistration(response, challenge, origin, rpId) {
  checkClient(response?.response?.clientDataJSON, 'webauthn.create', challenge, origin);
  const raw = unb64(response.response.attestationObject);
  const [attestation, end] = readCBOR(raw);
  if (end !== raw.length || !(attestation instanceof Map) || attestation.get('fmt') !== 'none' ||
      !(attestation.get('attStmt') instanceof Map) || attestation.get('attStmt').size) throw Error('attestation format rejected');
  const auth = attestation.get('authData');
  if (!Buffer.isBuffer(auth)) throw Error('missing authenticator data');
  const { counter } = checkAuthenticator(auth, rpId, true);
  if (auth.length < 55) throw Error('short attested credential');
  const idLength = auth.readUInt16BE(53), id = auth.subarray(55, 55 + idLength);
  if (!id.length || id.length !== idLength) throw Error('invalid credential ID');
  const [cose, keyEnd] = readCBOR(auth, 55 + idLength);
  if (keyEnd > auth.length || !(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1 ||
      !Buffer.isBuffer(cose.get(-2)) || cose.get(-2).length !== 32 ||
      !Buffer.isBuffer(cose.get(-3)) || cose.get(-3).length !== 32) throw Error('unsupported public key');
  // createPublicKey also checks that the point is on the selected curve.
  const key = createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b64(cose.get(-2)), y: b64(cose.get(-3)) }, format: 'jwk' });
  if (!same(id, unb64(response.id))) throw Error('credential ID mismatch');
  return { id: b64(id), publicKey: key.export({ format: 'jwk' }), counter };
}
export function verifyAuthentication(response, credential, challenge, origin, rpId) {
  if (response?.id !== credential.id) throw Error('wrong credential');
  const client = checkClient(response.response.clientDataJSON, 'webauthn.get', challenge, origin);
  const auth = unb64(response.response.authenticatorData);
  const { counter } = checkAuthenticator(auth, rpId);
  if (auth.length !== 37) throw Error('unexpected authenticator data');
  const signature = unb64(response.response.signature);
  const signed = Buffer.concat([auth, createHash('sha256').update(client).digest()]);
  const key = createPublicKey({ key: credential.publicKey, format: 'jwk' });
  if (!verifySignature('sha256', signed, key, signature)) throw Error('signature rejected');
  if (counter !== 0 && counter <= credential.counter) throw Error('signature counter did not increase');
  return counter;
}
