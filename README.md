# posta

**Mailbox API: create real IMAP and SMTP mailboxes on your own domain from code.**

posta is open-source email hosting with an API, built for developers and AI agents. Connect a domain you own, verify the DNS records, then create mailboxes with one API call or from a small web panel. Each mailbox is a real IMAP/SMTP mailbox. It is not a forwarding rule and not a sending-only API.

Hosted free early access: **https://posta.preved.co** (1 domain, 1 mailbox, 500 MB, 50 outgoing messages a day, no card).

## What you get
- Domain ownership and DNS verification (ownership TXT, MX, SPF, DKIM, DMARC)
- Mailboxes over IMAP (993) and SMTP (587 and 465), your own domain, TLS
- REST API with bearer keys: `/v1/me`, `/v1/domains`, `/v1/mailboxes`, `/v1/usage`
- Web panel for sign-up, domains, mailboxes and API keys
- Per-mailbox size and daily sending limits
- Audit log, and a backend interface: `mailcow` for real mailboxes, `dryrun` for development

## How it works
```
customer ──HTTPS──▶ posta (Django: panel + API) ──API──▶ Mailcow (Postfix, Dovecot, Rspamd)
mail client ───────IMAP 993 / SMTP 587, 465────────────▶ Mailcow
```
posta manages domains and mailboxes. [Mailcow](https://github.com/mailcow/mailcow-dockerized) runs the mail.

## Quick start (development)
```bash
git clone https://github.com/bexx2/posta.git && cd posta
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # keep MAIL_BACKEND=dryrun, set DB_* for PostgreSQL
cd app && python manage.py migrate && python manage.py runserver
```
For real mailboxes set `MAIL_BACKEND=mailcow` and give posta a Mailcow API key.

## API example
```bash
curl -s https://posta.preved.co/v1/mailboxes \
  -H "Authorization: Bearer $POSTA_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"acme.dev","local":"agent"}'
```
Full API reference is coming. Until then the endpoints above are stable.

Receive mail with Node.js over IMAP / Node.js ile IMAP üzerinden posta alma:
[example and setup / örnek ve kurulum](docs/receive-node.md).

## Who it is for
Developers shipping a new product, agencies setting up client domains, and people building AI agents that need their own email address.

## Project status
Early access. Outgoing mail to Outlook and Hotmail may be rejected for now. Bulk and marketing email is not allowed on the hosted service.

## License
[AGPL-3.0](LICENSE). You can read, run and modify posta. If you offer a modified version as a service, you must publish your changes under the same license. The name "posta" and its logo are not covered by the license.

Operated by HEYVANKA YAZILIM LTD. ŞTİ., Türkiye.
