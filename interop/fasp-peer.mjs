import { createHash, createPrivateKey, createPublicKey, randomBytes, randomUUID, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, openSync, closeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalizeFasp } from './fasp-canonical.mjs';

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const VERSION = 'fasp/1.0';
const DATE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;

function requireValue(value, label) { if (!value) throw new Error(label + ' required'); return value; }
function base64url(value, size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid base64url');
  const raw = Buffer.from(value, 'base64url');
  if (raw.toString('base64url') !== value || (size && raw.length !== size)) throw new Error('Invalid base64url size or encoding');
  return raw;
}
function time(delta = 0) { return new Date(Date.now() + delta).toISOString().replace('.000Z', 'Z'); }

export function createIdentity(seed = randomBytes(32)) {
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error('Ed25519 seed must be 32 bytes');
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: 'der', type: 'pkcs8' });
  const raw = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(SPKI.length);
  const pub = raw.toString('base64url');
  return { seed: seed.toString('base64url'), privateKey, publicKey: pub,
    systemId: 'fasp:system:' + createHash('sha256').update(raw).digest('base64url'),
    kid: 'ed25519-' + pub.slice(0, 8) };
}

export function signRecord(record, identity) {
  const { signature: ignored, ...unsigned } = record;
  const sig = sign(null, canonicalizeFasp(unsigned), identity.privateKey).toString('base64url');
  return { ...unsigned, signature: { alg: 'Ed25519', kid: identity.kid, value: sig } };
}

export function verifyRecord(record, publicKey, expectedKid) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error('Invalid signed object');
  const sig = record.signature;
  if (!sig || sig.alg !== 'Ed25519' || sig.kid !== expectedKid || typeof expectedKid !== 'string' || !expectedKid || expectedKid.length > 128) throw new Error('Invalid signature key');
  const raw = base64url(publicKey, 32);
  const key = createPublicKey({ key: Buffer.concat([SPKI, raw]), format: 'der', type: 'spki' });
  const { signature: ignored, ...unsigned } = record;
  if (!verify(null, canonicalizeFasp(unsigned), key, base64url(sig.value, 64))) throw new Error('Invalid signature');
  return true;
}

export function verifyCard(card) {
  if (!card || card.fasp !== VERSION || card.type !== 'id_card' || typeof card.public_key !== 'string') throw new Error('Invalid FASP card');
  const publicKey = base64url(card.public_key, 32);
  const expectedId = 'fasp:system:' + createHash('sha256').update(publicKey).digest('base64url');
  if (card.system_id !== expectedId) throw new Error('Mismatched card identity');
  for (const name of ['expires_at', 'issued_at']) {
    if (name === 'issued_at' && card[name] === undefined) continue;
    if (typeof card[name] !== 'string' || !DATE.test(card[name]) || !Number.isFinite(Date.parse(card[name]))) throw new Error('Invalid card timestamp');
  }
  if (Date.parse(card.expires_at) <= Date.now() ||
      (card.issued_at && Date.parse(card.issued_at) > Date.now() + 60000)) throw new Error('Expired or future-dated card');
  if (card.key_id !== undefined && card.key_id !== card.signature?.kid) throw new Error('Mismatched card key identifier');
  verifyRecord(card, card.public_key, card.signature?.kid);
  return card.system_id;
}

export function makeCard(identity, name = 'portable-node') {
  if (typeof name !== 'string' || name.length < 1 || name.length > 256) throw new Error('Invalid display name');
  return signRecord({ fasp: VERSION, type: 'id_card', system_id: identity.systemId,
    public_key: identity.publicKey, key_id: identity.kid, display_name: name,
    issued_at: time(), expires_at: time(30 * 86400000),
    endpoints: { profile: null, envelopes: null }, capabilities: [] }, identity);
}

export function makeEnvelope(identity, to, kind = 'heartbeat', payload = {}) {
  if (typeof to !== 'string' || !/^fasp:system:[A-Za-z0-9_-]{43}$/.test(to)) throw new Error('Invalid recipient');
  if (typeof kind !== 'string' || kind.length < 1 || kind.length > 128) throw new Error('Invalid kind');
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('Invalid payload');
  return signRecord({ fasp: VERSION, kind, message_id: randomUUID(), from: identity.systemId,
    to, issued_at: time(), expires_at: time(120000),
    nonce: randomBytes(12).toString('base64url'), payload }, identity);
}

export function initialize(file) {
  const identity = createIdentity();
  mkdirSync(dirname(resolve(file)), { recursive: true, mode: 0o700 });
  const handle = openSync(file, 'wx', 0o600);
  try { writeFileSync(handle, JSON.stringify({ seed: identity.seed, system_id: identity.systemId }) + '\n'); }
  finally { closeSync(handle); }
  return identity;
}
export function loadIdentity(file) {
  const stored = JSON.parse(readFileSync(file, 'utf8'));
  const identity = createIdentity(base64url(stored.seed, 32));
  if (stored.system_id !== identity.systemId) throw new Error('Identity file does not match the private key');
  return identity;
}
function options(argv) {
  const values = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i]?.startsWith('--') || !argv[i + 1]) throw new Error('Expected --option value');
    const name = argv[i].slice(2);
    if (Object.hasOwn(values, name)) throw new Error('Duplicate option');
    values[name] = argv[i + 1];
  }
  return values;
}
function checkedURL(input) {
  const url = new URL(input);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('Invalid URL');
  if (url.protocol === 'http:' && !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) throw new Error('HTTP allowed on loopback only');
  return url;
}
async function boundedJSON(response) {
  if (!response.body) throw new Error('Empty response');
  const reader = response.body.getReader();
  let size = 0, parts = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > 262144) { await reader.cancel(); throw new Error('Oversize peer response'); }
    parts.push(Buffer.from(value));
  }
  const data = JSON.parse(Buffer.concat(parts).toString('utf8'));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid response');
  return data;
}

export async function main(argv) {
  const [command, ...args] = argv;
  if (!['init', 'card', 'envelope', 'verify-card', 'pair', 'send'].includes(command)) throw new Error('Usage: init|card|envelope|verify-card|pair|send --state FILE [--url URL --peer-card FILE --to ID --kind KIND --payload JSON]');
  const opts = options(args);
  if (command === 'verify-card') {
    const card = JSON.parse(readFileSync(requireValue(opts.file, '--file'), 'utf8'));
    return { system_id: verifyCard(card), key_id: card.signature.kid };
  }
  const file = requireValue(opts.state, '--state');
  if (command === 'init') return { system_id: initialize(file).systemId, state: file };
  const identity = loadIdentity(file);
  if (command === 'card') return makeCard(identity, opts.name);
  if (command === 'envelope') return makeEnvelope(identity, requireValue(opts.to, '--to'), opts.kind, opts.payload ? JSON.parse(opts.payload) : {});
  const url = checkedURL(requireValue(opts.url, '--url'));
  if (command === 'pair') {
    const reply = await fetch(new URL('/pair/hello', url), { method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id_card: makeCard(identity) }), signal: AbortSignal.timeout(10000), redirect: 'error' });
    const result = await boundedJSON(reply);
    if (!reply.ok) throw new Error('Pair request rejected: ' + JSON.stringify(result));
    const card = requireValue(result.id_card, 'Remote card');
    const peerId = verifyCard(card);
    if (result.system_id !== peerId) throw new Error('Mismatched reply identity');
    verifyRecord(result, card.public_key, card.signature.kid);
    const code = createHash('sha256').update([identity.systemId, peerId].sort().join('|')).digest('base64url').slice(0, 12);
    if (result.pair_code !== code) throw new Error('Mismatched pairing fingerprint');
    return { state: 'pending', peer_id: peerId, pair_code: code, peer_card: card,
      note: 'Verify fingerprint out of band and approve on receiver. This command grants no permissions.' };
  }
  const pinned = JSON.parse(readFileSync(requireValue(opts['peer-card'], '--peer-card'), 'utf8'));
  const peerId = verifyCard(pinned);
  const live = await fetch(new URL('/profile', url), { signal: AbortSignal.timeout(10000), redirect: 'error' });
  if (!live.ok) throw new Error('Peer profile HTTP ' + live.status);
  const card = await boundedJSON(live);
  if (verifyCard(card) !== peerId || card.public_key !== pinned.public_key || card.signature.kid !== pinned.signature.kid) throw new Error('Remote identity differs from pinned peer');
  const envelope = makeEnvelope(identity, peerId, opts.kind, opts.payload ? JSON.parse(opts.payload) : {});
  const response = await fetch(new URL('/fasp/v1/envelopes', url), { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(envelope), signal: AbortSignal.timeout(15000), redirect: 'error' });
  return { status_code: response.status, message_id: envelope.message_id, response: await boundedJSON(response) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then(result => process.stdout.write(JSON.stringify(result) + '\n')).catch(error => {
    process.stderr.write('fasp-peer: ' + error.message + '\n');
    process.exitCode = 1;
  });
}
