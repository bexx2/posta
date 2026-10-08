# Changelog

## v0.1.0-beta (2026-10-08)
First public release.
- REST API v1: domains (add, verify, delete), mailboxes (create, list, delete), API keys with scopes, usage.
- Domain verification: ownership TXT and MX required; SPF, DKIM and DMARC checked and reported.
- Real IMAP (993) and SMTP (587, 465) mailboxes on top of Mailcow.
- Web panel: sign-up, email confirmation, domains, mailboxes, API keys.
- Free early-access plan: 1 domain, 1 mailbox, 500 MB, 50 outgoing messages a day.
- OpenAPI spec and LLM-readable docs at https://posta.preved.co/docs

Known limits: delivery to Outlook/Hotmail may be rejected while the sending IP builds reputation; no inbound webhook yet (poll IMAP); bulk and marketing mail is not allowed.
