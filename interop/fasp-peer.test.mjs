import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createIdentity, initialize, loadIdentity, makeCard, makeEnvelope, verifyCard, verifyRecord, main } from './fasp-peer.mjs';

test('independent Node peer persists a private key and emits a valid signed card', () => {
  const directory = mkdtempSync(join(tmpdir(), 'fasp-node-'));
  try {
    const state = join(directory, 'identity.json');
    const identity = initialize(state);
    assert.equal(loadIdentity(state).systemId, identity.systemId);
    assert.equal(statSync(state).mode & 0o077, 0);
    const card = makeCard(identity, 'portable-node');
    assert.equal(verifyCard(card), identity.systemId);
    assert.equal(card.key_id, card.signature.kid);
    assert.equal(card.endpoints.envelopes, null);
    assert.ok(!readFileSync(state, 'utf8').includes('private_key'));
    assert.throws(() => initialize(state));
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('signatures cover every field, including optional metadata', () => {
  const identity = createIdentity(Buffer.alloc(32, 11));
  const other = createIdentity(Buffer.alloc(32, 12));
  const card = makeCard(identity);
  assert.throws(() => verifyCard({ ...card, system_id: other.systemId }), /identity/);
  assert.throws(() => verifyCard({ ...card, display_name: 'changed' }), /signature/);
  assert.throws(() => verifyCard({ ...card, signature: { ...card.signature, value: card.signature.value + '=' } }), /base64url/);
  assert.equal(verifyRecord(card, identity.publicKey, identity.kid), true);
  assert.throws(() => verifyRecord(card, other.publicKey, identity.kid), /signature/);
});

test('envelopes use valid IDs, bounded lifetimes and strict JSON values', () => {
  const sender = createIdentity();
  const receiver = createIdentity();
  const envelope = makeEnvelope(sender, receiver.systemId, 'heartbeat', {});
  assert.equal(envelope.from, sender.systemId);
  assert.equal(envelope.to, receiver.systemId);
  assert.equal(envelope.fasp, 'fasp/1.0');
  assert.ok(Date.parse(envelope.expires_at) > Date.parse(envelope.issued_at));
  assert.throws(() => makeEnvelope(sender, 'other', 'heartbeat', {}), /recipient/);
  assert.throws(() => makeEnvelope(sender, receiver.systemId, 'heartbeat', []), /payload/);
  assert.throws(() => makeEnvelope(sender, receiver.systemId, 'heartbeat', { x: Infinity }), /non-finite/);
});

test('CLI creates signed messages without Python, WASM or third-party packages', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'fasp-node-cli-'));
  try {
    const state = join(directory, 'state.json');
    const initialized = await main(['init', '--state', state]);
    const card = await main(['card', '--state', state]);
    assert.equal(verifyCard(card), initialized.system_id);
    const message = await main(['envelope', '--state', state, '--to', initialized.system_id]);
    assert.equal(message.to, initialized.system_id);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
