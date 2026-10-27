Telegram HTML/JS Decoder Bot V3

Features:
- Extracts all embedded script blocks into separate formatted JavaScript files.
- Extracts the ENG protected-core block when present.
- Decodes literal JS hex/Unicode escape strings and readable Base64 candidates.
- Reports common obfuscation indicators.
- Never executes uploaded JavaScript.

Important: the supplied file uses an integrity-check wrapper and custom obfuscation. This bot helps inspect layers but cannot promise full source recovery or automatically reverse custom encryption/runtime-generated code.

Render:
Build Command: pip install -r requirements.txt
Start Command: python bot.py
Environment variable: BOT_TOKEN = token from @BotFather
Recommended service: Background Worker
