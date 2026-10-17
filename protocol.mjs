// SRF Phone Custodian public protocol v0.4. No fetch / network APIs.
export const domain = 'SRF-PHONE-WITNESS/ECDSA-P256/v0.4\0';
export const CHALLENGE = 'srf.phone.challenge.v0.4';
export const PUB = 'srf.phone.public.v0.4';
export const RECEIPT = 'srf.phone.receipt.v0.4';
export const CLAIM = 'srf.phone.signed_claim.v0.4';
export const ATTESTATION = 'PHONE_OBSERVED_CIPHERTEXT_BYTES';
export const MAX_BYTES = 1048576;
const enc = new TextEncoder();
export function canonical(o) {
  function walk(v) {
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) {
      const keys=Object.keys(v).sort();
      if(keys.some(k=> !/^[a-z_][a-z0-9_]*$/.test(k)))throw Error('KEY_NOT_ASCII');
      return '{'+keys.map(k=>JSON.stringify(k)+':'+walk(v[k])).join(',')+'}';
    }
    if(typeof v==='string' && /^[\x00-\x7f]*$/.test(v))return JSON.stringify(v);
    if(typeof v==='number' && Number.isSafeInteger(v))return String(v);
    throw Error('NON_SCALAR_OR_NONASCII');
  }
  return walk(o);
}
export function encode(s) { return enc.encode(s); }
export function fromBytes(bytes) { return new TextDecoder('utf-8',{fatal:true}).decode(bytes); }
export function b64u(bytes) {
  let s=''; for(const n of bytes)s+=String.fromCharCode(n);
  return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
}
export function unb64u(s) {
  if (typeof s!=='string' || s.length>8192 || !/^[A-Za-z0-9_-]+$/.test(s)) throw Error('BASE64URL_INVALID');
  const padded=s.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-s.length%4)%4);
  const out=Uint8Array.from(atob(padded), x=>x.charCodeAt(0));
  if(b64u(out)!==s)throw Error('NONCANONICAL_BASE64URL');
  return out;
}
export async function sha(bytes){const h=new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));return Array.from(h,v=>v.toString(16).padStart(2,'0')).join('');}
export async function publicDescriptor(spki){return {schema:PUB,algorithm:'ECDSA-P256-SHA256-P1363',spki_b64u:b64u(new Uint8Array(spki)),fingerprint:'sha256:'+await sha(spki)};}
export function checkChallenge(s) {
  const raw=fromBytes(unb64u(s));const c=JSON.parse(raw);
  if(raw!==canonical(c))throw Error('CHALLENGE_NOT_CANONICAL');
  const f=['schema','scope','challenge_id','nonce','sequence','prev_receipt_sha256','ciphertext_sha256','ciphertext_size_bytes','custodian_fingerprint','created_utc','expires_utc','source_head_sha256'].sort();
  if(JSON.stringify(Object.keys(c).sort())!==JSON.stringify(f))throw Error('CHALLENGE_FIELDS_INVALID');
  if(c.schema!==CHALLENGE || c.scope!=='SYNTHETIC_CIPHERTEXT_CUSTODY_ONLY')throw Error('SCOPE_DENIED');
  if(!/^[0-9a-f]{32}$/.test(c.challenge_id)||!/^[0-9a-f]{32}$/.test(c.nonce))throw Error('NONCE_INVALID');
  for(const k of ['prev_receipt_sha256','ciphertext_sha256','source_head_sha256']) if(!/^[0-9a-f]{64}$/.test(c[k]))throw Error('DIGEST_INVALID');
  if(!/^sha256:[0-9a-f]{64}$/.test(c.custodian_fingerprint))throw Error('PIN_INVALID');
  if(!Number.isSafeInteger(c.sequence)||c.sequence<1||c.sequence>1e6||!Number.isSafeInteger(c.ciphertext_size_bytes)||c.ciphertext_size_bytes<1||c.ciphertext_size_bytes>MAX_BYTES)throw Error('BOUNDS_INVALID');
  for(const k of ['created_utc','expires_utc'])if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(c[k])||!Number.isFinite(Date.parse(c[k])))throw Error('TIME_INVALID');
  const created=Date.parse(c.created_utc),expires=Date.parse(c.expires_utc),now=Date.now();
  if(expires-created>86400000||expires<=created||now>expires+120000||now+120000<created)throw Error('EXPIRED_OR_FUTURE');
  if(c.sequence===1 && c.prev_receipt_sha256!=='0'.repeat(64))throw Error('GENESIS_PREV_INVALID');
  if(c.sequence>1 && c.prev_receipt_sha256==='0'.repeat(64))throw Error('PREV_REQUIRED');
  return c;
}
export async function makeReceipt(privateKey, challengeB64, publicObj, fileBuffer, state={sequence:0,head:'0'.repeat(64)}, storageClaim='PHONE_FILE_ONLY') {
  const c=checkChallenge(challengeB64);
  if(c.custodian_fingerprint!==publicObj.fingerprint)throw Error('PIN_WRONG_KEY');
  if(c.sequence !== state.sequence+1 || c.prev_receipt_sha256!==state.head)throw Error('ROLLBACK_OR_REPLAY_REFUSED');
  if(storageClaim!=='PHONE_FILE_ONLY'&&storageClaim!=='CLOUD_UPLOAD_SELF_DECLARED')throw Error('STORAGE_CLAIM_INVALID');
  if(fileBuffer.byteLength!==c.ciphertext_size_bytes || fileBuffer.byteLength>MAX_BYTES || await sha(fileBuffer)!==c.ciphertext_sha256)throw Error('FILE_NOT_SAME_CIPHERTEXT');
  const claim={schema:CLAIM,challenge_b64u:challengeB64,custodian_fingerprint:publicObj.fingerprint,attestation:ATTESTATION,storage_claim:storageClaim};
  const data=encode(domain+canonical(claim));
  const sig = new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,data));
  if(sig.length!==64)throw Error('INVALID_P1363_SIGNATURE_LENGTH');
  const receipt={schema:RECEIPT,claim,signature_b64u:b64u(sig)};
  return {receipt,receipt_head:await sha(encode(canonical(receipt))),sequence:c.sequence};
}
