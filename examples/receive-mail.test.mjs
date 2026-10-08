import assert from 'node:assert/strict';
import test from 'node:test';
import { receiveLatest } from './receive-mail.mjs';

function fake({ empty = false, fail = false, connectFail = false } = {}) {
  const calls = [];
  return {
    calls, usable: !connectFail, mailbox: { exists: empty ? 0 : 2 },
    async connect() { calls.push('connect'); if (connectFail) throw new Error('connect'); },
    async getMailboxLock(path, options) {
      assert.equal(path, 'INBOX');
      assert.deepEqual(options, { readOnly: true });
      calls.push('lock');
      return { release() { calls.push('release'); } };
    },
    async fetchOne(range, query) {
      assert.equal(range, '*');
      assert.deepEqual(query, { uid: true, envelope: true });
      calls.push('fetch');
      if (fail) throw new Error('fetch');
      return { uid: 9, envelope: { subject: 'Example / Örnek' } };
    },
    async logout() { calls.push('logout'); },
    close() { calls.push('close'); }
  };
}

test('reads the newest envelope and releases the connection', async () => {
  const client = fake();
  assert.equal((await receiveLatest(client)).uid, 9);
  assert.deepEqual(client.calls, ['connect', 'lock', 'fetch', 'release', 'logout', 'close']);
});
test('an empty mailbox is not fetched', async () => {
  const client = fake({ empty: true });
  assert.equal(await receiveLatest(client), null);
  assert.deepEqual(client.calls, ['connect', 'lock', 'release', 'logout', 'close']);
});
test('a fetch error still releases the lock and connection', async () => {
  const client = fake({ fail: true });
  await assert.rejects(receiveLatest(client), /fetch/);
  assert.deepEqual(client.calls, ['connect', 'lock', 'fetch', 'release', 'logout', 'close']);
});
test('a failed connection is closed without a mailbox operation', async () => {
  const client = fake({ connectFail: true });
  await assert.rejects(receiveLatest(client), /connect/);
  assert.deepEqual(client.calls, ['connect', 'close']);
});
