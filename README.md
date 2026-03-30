# XSS Char Probe — Burp Suite Extension

A Burp Suite extension that actively injects XSS-relevant special characters
into every parameter of `text/html` requests, checks whether they reflect
back unencoded in the response, and suggests GET/POST method swaps.

> **For authorized penetration testing only.**

---

## How It Works

For every parameter in a proxied `text/html` request the extension:

1. Appends the probe string `xssP"><'\`` to the parameter value
2. Sends **one request per parameter** (all other params unchanged)
3. Searches the response for unencoded reflected characters after the `xssP` prefix
4. Detects the **injection context** (HTML text, HTML attribute, JS string, HTML tag)
5. Reports which characters reflected and what that means for exploitability

```
Original:   GET /search?q=hello
Probe sent: GET /search?q=xssP%22%3E%3C%27%60
Response:   ...xssP"><'`...   <-- HIGH: chars reflected unencoded
```

No full payloads are injected -- just the special characters needed to
determine what the server encodes vs. passes through.

---

## Features

| Feature | Detail |
|---------|--------|
| Special char injection | Probes `< > " ' \`` per parameter |
| Context detection | html_text / html_attr / html_tag / js_string |
| Deduplication | Same (host, path, param) never tested twice |
| Method swap test | Tests GET->POST and POST->GET once per endpoint |
| text/html only | Skips JS, JSON, XML, images -- reads raw Content-Type header |
| Severity rating | High / Medium / Low based on which chars reflected |
| Clean UI tab | "XSS Probe" tab in Burp with live log and cache reset button |

---

## Probe String

```
xssP"><'`
```

- `xssP` -- unique prefix to locate the reflection point in the response
- `"` -- breaks HTML attribute values (double quote)
- `>` -- closes HTML tags
- `<` -- opens new HTML tags / script blocks
- `'` -- breaks HTML attribute values (single quote)
- `` ` `` -- breaks template literals in JavaScript

---

## Injection Contexts & What They Mean

| Context | Reflected chars needed | Example bypass |
|---------|----------------------|----------------|
| `html_text` | `<` `>` | `<script>alert(1)</script>` |
| `html_attr` | `"` or `'` | `" onmouseover=alert(1) x="` |
| `html_tag` | `>` | `> <script>alert(1)</script>` |
| `js_string` | `"` or `'` | `";alert(1)//` |

---

## Installation

### Requirements
- Burp Suite Pro or Community Edition
- Jython 2.5+ standalone JAR configured in Burp

### Steps

1. Download [Jython standalone JAR](https://www.jython.org/download) if not already set up
2. In Burp: **Extender -> Options -> Python Environment** -> select the Jython JAR
3. **Extender -> Extensions -> Add**
   - Extension type: `Python`
   - Extension file: `xss_char_probe.py`
4. Click **Next** -- the "XSS Probe" tab should appear in Burp

---

## Usage

### Automatic (recommended)
Just browse through Burp proxy normally. The extension hooks into
`doPassiveScan` and fires a probe for every new `text/html` endpoint.

### Manual trigger
Right-click any request in Proxy/Target -> **Scan** -> the extension
will probe all parameters in that request.

### Test it
```
https://public-firing-range.appspot.com/reflected/parameter/body?q=a
```
Browse this URL through Burp -- the extension will probe `q` with
`xssP"><'\`` and report a High finding since all chars reflect unencoded.

---

## Output Example

```
[ XSS Char Probe v2.0 loaded ]
Probe string: xssP"><'`
Only scanning Content-Type: text/html responses.
------------------------------------------------------------
[High] https://example.com/search?q=a | param=q | reflected: <, >, ", ' | ctx=html_text
[Medium] https://example.com/profile?name=x | param=name | reflected: " | ctx=html_attr
[MethodSwap] GET -> GET-to-POST | https://example.com/login | status=200
```

---

## Scanner Issues Reported

| Issue name | Severity | Confidence |
|-----------|----------|------------|
| XSS Probe: Special Chars Reflected Unencoded | High / Medium / Low | Firm |
| XSS Probe: Method Swap Accepted | Information | Certain |

---

## Limitations

- Not a full XSS scanner -- confirms char reflection only, not exploitability
- Does not test DOM-based XSS (no browser rendering)
- Does not test stored XSS (no second request to a sink)
- Jython 2.5 compatible (no f-strings, no Python 3 syntax)

---

## File Structure

```
xss-char-probe/
  xss_char_probe.py   -- Main Burp extension
  README.md           -- This file
  CHANGELOG.md        -- Version history
  docs/
    context_guide.md  -- Injection context reference
  screenshots/        -- Add your own screenshots here
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md)

---

## Disclaimer

This tool is intended for use against systems you own or have explicit
written permission to test. Unauthorized use against third-party systems
is illegal. The author accepts no liability for misuse.
