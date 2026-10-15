// Exercise the real TypeScript SDK after Node's built-in type stripping.
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
const input = JSON.parse(readFileSync(0, 'utf8'));
const directory = mkdtempSync(join(tmpdir(), 'fasp-node-channel-'));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const waitFor = async condition => {
  for (let i = 0; i < 200; i++) { if (condition()) return; await sleep(10); }
  throw new Error('Channel event did not arrive');
};
try {
  writeFileSync(join(directory, 'package.json'), '{"type":"module"}');
  for (const file of ['fasp', 'crypto', 'fsjson', 'timestamps']) {
    const source = readFileSync(resolve('bridge_core', `${file}.ts`), 'utf8');
    writeFileSync(join(directory, `${file}.js`), stripTypeScriptTypes(source));
  }
  copyFileSync(resolve('bridge_core/fasp_canonical.mjs'), join(directory, 'fasp_canonical.mjs'));
  const { FaspClient } = await import(pathToFileURL(join(directory, 'fasp.js')));
  if (input.url) {
    const client = new FaspClient(join(directory, 'network-identity'));
    const hello = await client.hello(input.url, client.buildIdCard('real-node-client', []));
    await client.confirmSelf(input.url, client.systemId, hello.pair_code, input.admin_token);
    let received;
    const reply = new Promise(resolve => { received = resolve; });
    const channel = await client.openChannel(input.url, message => received(message));
    const request = client.buildEnvelope('heartbeat', hello.system_id, {});
    try {
      channel.send(request);
      let timer;
      const response = await Promise.race([reply, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Real channel reply timed out')), 5000);
      })]).finally(() => clearTimeout(timer));
      assert.equal(response.type, 'heartbeat'); assert.equal(response.in_reply_to, request.message_id);
      process.stdout.write(JSON.stringify({registered:true, correlated:true}));
    } finally { channel.close(); }
  } else {
  const frames = [], statuses = [], messages = [];
  let currentCard = input.card, closeBeforeOpen = false, fetches = 0;
  globalThis.fetch = async url => {
    fetches++;
    return new Response(JSON.stringify(url.endsWith('/pair/hello') ? {
      type: 'hello.ready', system_id: currentCard.system_id, id_card: currentCard,
      pair_code: 'test', pairing_required: false,
    } : currentCard), { status: 200 });
  };
  class Socket extends EventTarget {
    static OPEN = 1;
    static instances = [];
    readyState = 0;
    bufferedAmount = 0;
    constructor() {
      super(); Socket.instances.push(this);
      queueMicrotask(() => {
        if (closeBeforeOpen) { this.close(); return; }
        this.readyState = 1; this.dispatchEvent(new Event('open'));
      });
    }
    send(line) {
      const record = JSON.parse(line); frames.push(record);
      assert.equal(record.to, input.card.system_id, 'registration must target the receiver');
      if (record.kind === 'heartbeat') queueMicrotask(() => this.dispatchEvent(new MessageEvent('message', {
        data: JSON.stringify({type: 'heartbeat', in_reply_to: record.message_id}),
      })));
    }
    close() {
      if (this.readyState === 3) return;
      this.readyState = 3;
      this.dispatchEvent(new Event('close'));
    }
  }
  globalThis.WebSocket = Socket;
  const client = new FaspClient(join(directory, 'identity'));
  await assert.rejects(client.openChannel('http://peer', () => {}), error => error.code === 'auth.peer_required');
  const ownCard = client.buildIdCard('node-test', []);
  await client.hello('http://peer', ownCard);
  const channel = await client.openChannel('http://peer', message => messages.push(message), value => statuses.push(value));
  assert.notEqual(client.systemId, input.card.system_id);
  assert.equal(frames[0].kind, 'heartbeat');
  const first = Socket.instances.at(-1);
  first.bufferedAmount = 256 * 1024;
  assert.throws(() => channel.send(client.buildEnvelope('heartbeat', input.card.system_id, {})), error => error.code === 'channel.queue_full');
  first.bufferedAmount = 0;
  assert.throws(() => channel.send(client.buildEnvelope('heartbeat', client.systemId, {})), error => error.code === 'auth.wrong_audience');
  const expired = client.buildEnvelope('heartbeat', input.card.system_id, {});
  expired.expires_at = '2000-01-01T00:00:00Z';
  assert.throws(() => channel.send(expired), error => error.code === 'channel.expired');
  first.close();
  assert.throws(() => channel.send(client.buildEnvelope('heartbeat', input.card.system_id, {}, {delivery:'volatile', receiverInstance:'test'})), error => error.code === 'channel.offline');
  const stale = client.buildEnvelope('heartbeat', input.card.system_id, {});
  stale.expires_at = new Date(Date.now() + 30).toISOString();
  channel.send(stale);
  const queued = client.buildEnvelope('heartbeat', input.card.system_id, {});
  channel.send(queued);
  let bounded = false;
  for (let i = 0; i < 50; i++) {
    try { channel.send(client.buildEnvelope('heartbeat', input.card.system_id, {padding:'x'.repeat(40000)})); }
    catch (error) { assert.equal(error.code, 'channel.queue_full'); bounded = true; break; }
  }
  assert.ok(bounded, 'Reconnect buffer must enforce its byte budget');
  await waitFor(() => statuses.filter(x => x === 'open').length >= 2);
  await waitFor(() => frames.some(f => f.message_id === queued.message_id));
  assert.ok(!frames.some(f => f.message_id === stale.message_id));
  assert.ok(messages.some(m => m.error?.code === 'channel.expired'));
  // A valid but different signed identity at the same URL must stop reconnecting.
  currentCard = input.other_card;
  Socket.instances.at(-1).close();
  await waitFor(() => statuses.at(-1) === 'closed');
  assert.ok(messages.some(m => m.error?.code === 'auth.identity_mismatch'));
  assert.throws(() => channel.send(queued), error => error.code === 'channel.closed');
  channel.close();
  const stoppedFetches = fetches;
  await sleep(550);
  assert.equal(fetches, stoppedFetches, 'Explicit close must stop reconnection');
  currentCard = input.card; closeBeforeOpen = true;
  await assert.rejects(client.openChannel('http://peer', () => {}), /before registration/);
  process.stdout.write(JSON.stringify({ public_key: ownCard.public_key, frames, statuses }));
  }
} finally { rmSync(directory, {recursive:true, force:true}); }
