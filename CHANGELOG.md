# Changelog

All notable changes to XSS Char Probe are documented here.

---

## [2.0] - 2024

### Changed (breaking)
- Complete rewrite from passive observer to active char-injection scanner
- Extension now sends one probe request per parameter instead of only
  inspecting responses that happen to pass through the proxy

### Added
- Probe string `xssP"><'\`` injected per parameter
- Context detection: html_text / html_attr / html_tag / js_string
- Method swap test: GET->POST and POST->GET with real HTTP request
- Severity logic based on which characters reflected
- Dedup on (host, path, param_name) -- never re-tests the same param
- "XSS Probe" Burp UI tab with live log and dedup cache reset button

### Removed
- Old passive body-scan logic (unreliable, too many false positives)
- Broad MIME-type matching (now strictly text/html via raw header check)

---

## [1.3] - 2024

### Fixed
- SyntaxError in Jython 2.5: added `# -*- coding: utf-8 -*-` declaration
- Removed all non-ASCII characters from source (arrows, em-dashes, smart quotes)

### Changed
- Switched Content-Type check from Burp's `getStatedMimeType()` to raw
  response header parsing for accuracy

---

## [1.2] - 2024

### Added
- Strict Content-Type: text/html filter (skips JS, XML, JSON, binary)
- `_get_content_type_header()` helper reads raw headers

### Changed
- Removed JS and XML from MIME_TYPES list

---

## [1.1] - 2024

### Added
- GET->POST and POST->GET method swap suggestions
- Parameter reflection check against response body
- Deduplication by (host, path)

---

## [1.0] - 2024

### Initial release
- Passive scanner: detects unencoded XSS chars in HTML responses
- Burp UI tab with findings log
- IScanIssue integration for Scanner issues panel
