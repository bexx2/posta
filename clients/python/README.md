# posta-sdk (Python)

Python client for [posta](https://posta.preved.co): connect your own domain, create real IMAP/SMTP mailboxes with one API call, send, get webhooks, and wait for incoming mail.

```sh
pip install "git+https://github.com/bexx2/posta.git#subdirectory=clients/python"
```

```python
from posta import Posta, Inbox

p = Posta()                                   # reads POSTA_KEY (create a key in the dashboard)
d = p.domains.create("example.com")           # publish d["dns"] records at your DNS provider
p.domains.verify(d["id"])                     # or just wait: we check every 15 minutes
box = p.mailboxes.create(d["id"], "agent", "a-long-random-passphrase")

p.mailboxes.send(box["id"], "you@example.net", "Hello", text="Sent by my agent.")   # needs mail:send scope

with Inbox("agent@example.com", "a-long-random-passphrase") as inbox:
    msg = inbox.wait_for(subject_contains="verification code", timeout=180)
    print(msg.from_, msg.subject, msg.text)
```

Webhooks (no polling): `p.mailboxes.set_webhook(box["id"], "https://your-app/hook")` returns a secret; check each request with `posta.verify_webhook(secret, request.headers["Posta-Signature"], raw_body)`.

Errors raise `PostaError` with a stable `code` (`plan_limit`, `daily_limit`, `domain_not_verified`, …). Reading is read-only: `Inbox` never marks mail as seen or deletes it. Licence: AGPL-3.0.
