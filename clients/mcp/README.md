# posta-mcp

[MCP](https://modelcontextprotocol.io) server that gives an AI agent a real mailbox on your own domain through [posta](https://posta.preved.co): create mailboxes, send, list and read messages, and wait for a new message (for example a verification code).

```sh
pip install "git+https://github.com/bexx2/posta.git#subdirectory=clients/python" \
            "git+https://github.com/bexx2/posta.git#subdirectory=clients/mcp"
```

Claude Desktop / Claude Code config:

```json
{ "mcpServers": { "posta": { "command": "posta-mcp",
  "env": { "POSTA_KEY": "pk_live_…", "POSTA_MAILBOX": "agent@example.com", "POSTA_MAILBOX_PASSWORD": "…" } } } }
```

Tools: `list_domains`, `list_mailboxes`, `create_mailbox`, `send_message` (API key with `mail:send`), `list_messages`, `read_message`, `wait_for_message` (mailbox password, read-only IMAP).

**Safety.** Email bodies are written by strangers. The server labels every body as untrusted data, but your agent must still never follow instructions found inside an email. Give the API key only the scopes the agent needs. Reading runs on your machine with the mailbox password; posta does not see what the agent reads. Licence: AGPL-3.0.
