# Receive mail with Node.js / Node.js ile posta alma

The REST API provisions mailboxes; receive mail through IMAP using the **mailbox password**, not a bearer API key. Use the mail server hostname shown in the panel's connection settings (your deployment's MX target), not automatically the web/API hostname.

REST API posta kutularını oluşturur; postayı bearer API anahtarıyla değil **posta kutusu parolasıyla** IMAP üzerinden alın. Web/API adresini otomatik kullanmak yerine paneldeki bağlantı ayarlarında gösterilen posta sunucusunu (kurulumunuzun MX hedefini) kullanın.

Install Node.js 20 or newer, then run from the repository root / Node.js 20 veya üzerini kurun, ardından depo kökünde çalıştırın:

```sh
npm install --no-save --package-lock=false imapflow
export POSTA_IMAP_HOST='mail.example.com'
export POSTA_MAILBOX_USER='agent@example.com'
read -r -s -p 'Mailbox password / Posta kutusu parolası: ' POSTA_MAILBOX_PASSWORD
export POSTA_MAILBOX_PASSWORD
node examples/receive-mail.mjs
unset POSTA_MAILBOX_PASSWORD
```

The password prompt uses Bash. Never commit credentials or disable TLS verification. The example uses TLS on port 993, opens INBOX read-only, and prints only the latest envelope (UID, sender, subject and date), not the body. It does not mark messages as read or delete them. Output is private message metadata: avoid sharing logs. An empty inbox is handled without a fetch. The lock and connection are released on errors too.

Parola istemi Bash içindir. Kimlik bilgilerini commit etmeyin, TLS doğrulamasını kapatmayın. Örnek 993 portunda TLS kullanır, INBOX'u salt okunur açar ve gövde yerine yalnız son zarfı (UID, gönderen, konu ve tarih) yazdırır. İletileri okundu işaretlemez veya silmez. Çıktı özel ileti üstverisidir; kayıtları paylaşmayın. Boş kutuda fetch yapılmaz. Hatalarda da kilit ve bağlantı bırakılır.

Offline example checks / Çevrimdışı örnek testleri:

```sh
node --test examples/receive-mail.test.mjs
```

These checks use a fake client, not a live mailbox. The `dryrun` backend does not serve IMAP; live use requires a provisioned real mailbox. This repository example does not modify the separately hosted `/docs` page.

Bu testler canlı posta kutusu yerine sahte istemci kullanır. `dryrun` arka ucu IMAP sunmaz; canlı kullanım için gerçek bir posta kutusu gerekir. Bu depo örneği ayrı barındırılan `/docs` sayfasını değiştirmez.

API reference / API kaynağı: [ImapFlow client](https://imapflow.com/docs/api/imapflow-client/).
