import { pathToFileURL } from 'node:url';

// Read the newest envelope without downloading bodies or changing flags.
// Gövdeleri indirmeden veya bayrakları değiştirmeden son zarfı oku.
export async function receiveLatest(client) {
  try {
    await client.connect();
    const lock = await client.getMailboxLock('INBOX', { readOnly: true });
    try {
      if (client.mailbox.exists === 0) return null;
      return await client.fetchOne('*', { uid: true, envelope: true });
    } finally {
      lock.release();
    }
  } finally {
    try {
      if (client.usable) await client.logout();
    } finally {
      client.close();
    }
  }
}

async function main() {
  const { POSTA_IMAP_HOST: host, POSTA_MAILBOX_USER: user,
    POSTA_MAILBOX_PASSWORD: pass } = process.env;
  if (!host || !user || !pass) {
    throw new Error('Set IMAP host, mailbox user and password / IMAP sunucusu, posta kutusu kullanıcısı ve parolasını ayarlayın.');
  }
  const { ImapFlow } = await import('imapflow');
  const message = await receiveLatest(new ImapFlow({
    host, port: 993, secure: true, auth: { user, pass }, logger: false
  }));
  // This includes private message metadata; do not share terminal logs.
  // Özel ileti üstverisi içerir; terminal kayıtlarını paylaşmayın.
  console.log(message ? JSON.stringify({ uid: message.uid,
    from: message.envelope?.from, subject: message.envelope?.subject,
    date: message.envelope?.date }, null, 2)
    : 'INBOX is empty / INBOX boş.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => {
    console.error('Unable to receive mail; check credentials and IMAP host / Posta alınamadı; kimlik bilgilerini ve IMAP sunucusunu kontrol edin.');
    process.exitCode = 1;
  });
}
