# Telegram Claude Server

Custom Telegram channel plugin for [Claude Code](https://claude.com/claude-code), replacing the stock plugin with a comprehensive bot that supports 17 outbound tools, 17 inbound message handlers, inline keyboards, message entity forwarding, and auto-download of all file types.

Runs as a systemd service on a Raspberry Pi 5 (or any Linux box with Bun installed).

## Architecture

```
Telegram <──> grammy bot <──> MCP server <──> Claude Code (channel mode)
                                    │
                              server.ts (this repo)
```

- **server.ts** — The MCP server + grammy bot. Handles all Telegram API interaction, access control, file downloads, and message routing.
- **claude-telegram-daemon** — Bash wrapper that starts Claude Code in channel mode with a PTY, handles trust prompts, and manages the process lifecycle.
- **claude-telegram.service** — systemd unit for auto-start, restart on failure, and process isolation.

## Features

### Outbound tools (what Claude can do)

| Tool | Description |
|------|-------------|
| `reply` | Text with HTML/MarkdownV2 formatting, file attachments, link preview control, **inline keyboards** |
| `react` | Emoji reactions on messages |
| `edit_message` | Edit previously sent messages |
| `delete_message` | Delete sent messages |
| `send_photo` | Send photos by path, URL, or file_id |
| `send_document` | Send documents by path, URL, or file_id |
| `send_voice` | Send OGG/OPUS voice notes |
| `send_animation` | Send GIFs/MP4 animations |
| `send_media_group` | Send 2-10 photos/documents as an album |
| `send_location` | Send GPS coordinates |
| `forward_message` | Forward with "Forwarded from" header |
| `copy_message` | Forward without attribution header |
| `pin_message` | Pin messages in chats |
| `unpin_message` | Unpin messages |
| `download_attachment` | Manually download files too large for auto-download |

### Inbound handlers (what Claude receives)

| Message type | Auto-download? | Extra metadata |
|-------------|---------------|----------------|
| Text | — | `text_html` (preserves bold/italic/links/code as HTML) |
| Photo | Yes | `image_path` |
| Document | Yes (≤20MB) | `attachment_path`, mime, name |
| Voice | Yes | `attachment_path`, duration |
| Audio | Yes | `attachment_path`, duration, title |
| Video | Yes (≤20MB) | `attachment_path`, duration |
| Video note | Yes | `attachment_path`, duration |
| Animation (GIF) | Yes | `attachment_path`, duration |
| Sticker (WebP) | Yes | Set name, emoji, type |
| Location | — | Latitude, longitude, accuracy |
| Contact | — | Name, phone, telegram_id |
| Poll | — | Question, options, type |
| Venue | — | Title, address, coordinates |
| Edited messages | — | `is_edit` flag |
| Callback queries | — | `is_callback`, `callback_data` from inline keyboards |

### Message context

Every inbound message includes rich metadata:

- **`user_name`** — sender's display name (first + last)
- **`text_html`** — formatted version with `<b>`, `<i>`, `<a>`, `<code>`, etc.
- **`reply_to_msg_id`**, **`reply_to_text`**, **`reply_to_user`** — quoted message context
- **`forward_from`**, **`forward_from_chat`** — forwarded message origin
- **`chat_title`** — group/supergroup name
- **`is_edit`** — `"true"` when a message was edited
- **`is_callback`** — `"true"` when an inline keyboard button was pressed

### Inline keyboards

Claude can send interactive buttons:

```json
{
  "chat_id": "123",
  "text": "Choose an option:",
  "inline_keyboard": [
    [
      {"text": "Yes", "callback_data": "confirm"},
      {"text": "No", "callback_data": "cancel"}
    ],
    [
      {"text": "Open docs", "url": "https://example.com"}
    ]
  ]
}
```

When a user presses a button, Claude receives a callback notification with `callback_data`.

## Setup

### Prerequisites

- [Bun](https://bun.sh) runtime
- [Claude Code](https://claude.com/claude-code) CLI installed
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

### 1. Install dependencies

```bash
bun install
```

### 2. Configure bot token

Save your token to `~/.claude/channels/telegram/.env`:

```bash
mkdir -p ~/.claude/channels/telegram
echo "TELEGRAM_BOT_TOKEN=your_token_here" > ~/.claude/channels/telegram/.env
chmod 600 ~/.claude/channels/telegram/.env
```

Or use the Claude Code skill: `/telegram:configure <token>`

### 3. Deploy the custom server.ts

Copy `server.ts` over the stock plugin:

```bash
cp server.ts ~/.claude/plugins/cache/claude-plugins-official/telegram/0.0.1/server.ts
```

> **Note:** Plugin updates will overwrite this file. Re-copy after updates.

### 4. Set up the systemd service

```bash
# Copy the daemon script
sudo cp claude-telegram-daemon /home/$USER/.local/bin/claude-telegram-daemon
chmod +x ~/.local/bin/claude-telegram-daemon

# Install and enable the service
sudo cp claude-telegram.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now claude-telegram.service
```

### 5. Pair your Telegram account

1. DM your bot on Telegram — it replies with a 6-char pairing code
2. In Claude Code: `/telegram:access pair <code>`
3. Lock down access: `/telegram:access policy allowlist`

## Access control

Access is managed via `~/.claude/channels/telegram/access.json`. See `access.example.json` for the schema.

| Policy | Behavior |
|--------|----------|
| `pairing` | Unknown senders get a pairing code. Approve with `/telegram:access pair <code>`. |
| `allowlist` | Only `allowFrom` user IDs can reach Claude. Recommended for production. |
| `disabled` | All DMs silently dropped. |

Groups require explicit registration via `/telegram:access group add <groupId>`.

### Skills

- **`/telegram:access`** — Manage pairings, allowlists, group policies, delivery settings
- **`/telegram:configure`** — Set up or check bot token and channel status

## Configuration options

Set via `/telegram:access set <key> <value>`:

| Key | Values | Default | Description |
|-----|--------|---------|-------------|
| `ackReaction` | emoji / `""` | none | React to incoming messages to confirm receipt |
| `replyToMode` | `off` / `first` / `all` | `first` | Which chunks get Telegram reply threading |
| `textChunkLimit` | 1-4096 | 4096 | Max chars per message before splitting |
| `chunkMode` | `length` / `newline` | `length` | Split on paragraph boundaries or hard length |
| `mentionPatterns` | JSON array | none | Extra regex patterns to trigger in groups |

## File structure

```
.
├── server.ts                  # MCP server + grammy bot (main plugin)
├── claude-telegram-daemon     # Bash wrapper for systemd
├── claude-telegram.service    # systemd unit file
├── package.json               # Bun dependencies
├── bun.lock                   # Lock file
├── .mcp.json                  # MCP server configuration
├── skills/
│   ├── access/SKILL.md        # /telegram:access skill definition
│   └── configure/SKILL.md     # /telegram:configure skill definition
├── access.example.json        # Example access control config
└── .gitignore
```

## License

Apache-2.0
