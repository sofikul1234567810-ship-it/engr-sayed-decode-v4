import os, re, io, json, base64, zipfile, hashlib
from pathlib import Path
import telebot
import jsbeautifier

TOKEN = os.getenv("BOT_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("Set BOT_TOKEN in environment.")
bot = telebot.TeleBot(TOKEN, parse_mode=None)
MAX_BYTES = 20 * 1024 * 1024

def beautify(s):
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.preserve_newlines = True
        return jsbeautifier.beautify(s, opts)
    except Exception:
        return s

def readable_text(data):
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ratio = sum(c.isprintable() or c in "\r\n\t" for c in s) / max(1, len(s))
    return s if ratio >= 0.92 else None

def decode_base64(source, outputs, report):
    patterns = [
        re.compile(r"(?P<q>[\"'`])([A-Za-z0-9+/]{32,}={0,2})(?P=q)"),
        re.compile(r"atob\(\s*([\"'])([A-Za-z0-9+/]{16,}={0,2})\1\s*\)"),
    ]
    seen, count = set(), 0
    for pattern in patterns:
        for match in pattern.finditer(source):
            raw = match.group(2)
            if raw in seen:
                continue
            seen.add(raw)
            try:
                data = base64.b64decode(raw + "=" * ((-len(raw)) % 4), validate=False)
                decoded = readable_text(data)
                if not decoded or len(decoded) < 20:
                    continue
                count += 1
                ext = "html" if re.search(r"<(?:!doctype|html|script|body)\b", decoded, re.I) else "txt"
                name = f"decoded_base64_{count:03d}.{ext}"
                outputs[name] = decoded
                report.append(f"Base64 candidate {count}: {len(raw)} encoded chars -> {name}")
                if count >= 40:
                    report.append("Stopped after 40 candidates.")
                    return
            except Exception:
                continue
    if count == 0:
        report.append("No clearly readable Base64 text payloads found.")

def decode_js_escapes(source, outputs, report):
    pat = re.compile(r"([\"'])(?P<body>(?:\\.|(?!\1).)*?)\1")
    found = []
    for match in pat.finditer(source):
        body = match.group("body")
        if not re.search(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})", body):
            continue
        def replace_escape(m):
            token = m.group(0)
            try:
                return chr(int(token[2:], 16))
            except Exception:
                return token
        decoded = re.sub(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", replace_escape, body)
        if decoded != body and len(found) < 1000:
            found.append({"original": body, "decoded": decoded})
    outputs["decoded_js_string_escapes.json"] = json.dumps(found, indent=2, ensure_ascii=False)
    report.append(f"JS hex/Unicode string escapes decoded: {len(found)}")

def analyze(data, filename):
    source = data.decode("utf-8-sig", errors="replace")
    outputs = {}
    report = [
        "Telegram HTML/JS Decoder V3 - static analysis",
        f"Input: {filename}",
        f"Bytes: {len(data)}",
        f"SHA-256: {hashlib.sha256(data).hexdigest()}",
        "Uploaded source was never executed."
    ]
    orig = "00_original_source.html" if filename.lower().endswith((".html", ".htm", ".xhtml")) else "00_original_source.txt"
    outputs[orig] = source
    scripts = re.findall(r"<script\b([^>]*)>([\s\S]*?)</script\s*>", source, re.I)
    report.append(f"Embedded script blocks found: {len(scripts)}")
    for i, (attrs, code) in enumerate(scripts, 1):
        ident = re.search(r"\bid\s*=\s*[\"']([^\"']+)", attrs, re.I)
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", ident.group(1)) if ident else f"script_{i:02d}"
        outputs[f"scripts/{i:02d}_{label}.js"] = beautify(code)
        if re.search(r"\bid\s*=\s*[\"']eng-protected-core[\"']", attrs, re.I):
            outputs["protected_core_raw.js"] = code
            report.append(f"Protected core extracted ({len(code)} chars).")

    decode_js_escapes(source, outputs, report)
    decode_base64(source, outputs, report)
    indicators = {
        "eval_calls": len(re.findall(r"\beval\s*\(", source)),
        "Function_constructor": len(re.findall(r"\bFunction\s*\(", source)),
        "atob_calls": len(re.findall(r"\batob\s*\(", source)),
        "fromCharCode_calls": len(re.findall(r"String\s*\.\s*fromCharCode", source)),
        "hex_unicode_escapes": len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", source)),
        "obfuscator_identifiers": len(re.findall(r"\b_0x[0-9a-fA-F]+\b", source)),
    }
    outputs["static_obfuscation_indicators.json"] = json.dumps(indicators, indent=2)
    report.append("Static obfuscation indicators: " + json.dumps(indicators))
    if "87081521" in source and "eng-protected-core" in source:
        report.append("WARNING: ENG protected-core integrity wrapper detected; custom runtime obfuscation is not automatically reversed.")
        report.append("A fallback Base64 page may be an error page rather than the actual app.")
    outputs["REPORT.txt"] = "\n".join(report) + "\n"
    outputs["README_RESULTS.txt"] = (
        "V3 output guide\n"
        "- scripts/: extracted, formatted embedded JavaScript\n"
        "- protected_core_raw.js: extracted protected core, if detected\n"
        "- decoded_base64_*: readable Base64 text candidates\n"
        "- decoded_js_string_escapes.json: decoded literal JS escape strings\n"
        "- REPORT.txt: scan report\n\n"
        "This tool never executes uploaded code. It cannot guarantee reversing custom encryption, integrity checks, or runtime-generated control flow.\n"
    )
    return outputs, report

def zip_result(outputs, filename):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, value in outputs.items():
            archive.writestr(name, value.encode("utf-8", errors="replace"))
    stream.seek(0)
    stream.name = Path(filename).stem + "_decoder_v3.zip"
    return stream

@bot.message_handler(commands=["start", "help"])
def start(message):
    bot.reply_to(message, "HTML/JS Decoder V3 ready. Send .html/.htm/.js/.txt (max 20 MB). I extract and format scripts, decode static Base64 and JS escape strings, then return a ZIP report. Uploaded code is never executed; custom obfuscation may remain.")

@bot.message_handler(content_types=["document"])
def receive_document(message):
    doc = message.document
    filename = doc.file_name or "upload.txt"
    if not filename.lower().endswith((".html", ".htm", ".xhtml", ".js", ".txt")):
        bot.reply_to(message, "Please send .html, .htm, .js or .txt.")
        return
    if doc.file_size and doc.file_size > MAX_BYTES:
        bot.reply_to(message, "File exceeds 20 MB limit.")
        return
    status = bot.reply_to(message, "V3 static decode in process…")
    try:
        info = bot.get_file(doc.file_id)
        raw = bot.download_file(info.file_path)
        if len(raw) > MAX_BYTES:
            bot.edit_message_text("File exceeds 20 MB limit.", message.chat.id, status.message_id)
            return
        outputs, report = analyze(raw, filename)
        bot.delete_message(message.chat.id, status.message_id)
        result = zip_result(outputs, filename)
        bot.send_document(message.chat.id, result, caption=f"V3 static analysis complete. Files: {len(outputs)}. See REPORT.txt in ZIP.")
    except Exception as exc:
        try:
            bot.edit_message_text("Processing error: " + str(exc)[:250], message.chat.id, status.message_id)
        except Exception:
            bot.reply_to(message, "Processing error: " + str(exc)[:250])

print("Decoder V3 polling started.")
bot.infinity_polling(skip_pending=True, timeout=30, long_polling_timeout=30)
