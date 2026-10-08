# Changelog

## Unreleased
- Pro plan: 1 domain, 10 mailboxes, USD 100 a year, paid once by card through iyzico (Checkout Form). No automatic renewal.
  Orders keep the buyer type, accepted terms version, time and IP. A payment that iyzico confirms but that fails our checks goes to `review` and alerts the operator; `confirm_order` applies it by hand.
  `reconcile_orders` applies payments whose callback never arrived. `pro_lifecycle` sends the 30 and 7 day reminders and, after a 14 day grace period, moves the account to the free plan and suspends the extra mailboxes (they come back if you renew). Deleting suspended mailboxes is not implemented yet. `end_pro` ends Pro after a refund.
  Payment is off unless `PAYMENTS_ENABLED=1` and the `IYZICO_*` settings are present.
- Sign-up rejects email addresses without a top-level domain (for example `name@example`).
- Operator notification email on new sign-ups, domains and mailboxes (`NOTIFY_EMAIL`, empty = off).

## v0.1.0-beta (2026-10-08)
First public release.
- REST API v1: domains (add, verify, delete), mailboxes (create, list, delete), API keys with scopes, usage.
- Domain verification: ownership TXT and MX required; SPF, DKIM and DMARC checked and reported.
- Real IMAP (993) and SMTP (587, 465) mailboxes on top of Mailcow.
- Web panel: sign-up, email confirmation, domains, mailboxes, API keys.
- Free early-access plan: 1 domain, 1 mailbox, 500 MB, 50 outgoing messages a day.
- OpenAPI spec and LLM-readable docs at https://posta.preved.co/docs

Known limits: delivery to Outlook/Hotmail may be rejected while the sending IP builds reputation; no inbound webhook yet (poll IMAP); bulk and marketing mail is not allowed.
