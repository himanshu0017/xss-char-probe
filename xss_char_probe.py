# -*- coding: utf-8 -*-
"""
XSS Special Character Reflection Scanner - Burp Suite Extension
================================================================
Author  : For authorized pentesting only
Purpose : For each parameter in a text/html request, inject a probe string
          of XSS-relevant special characters and check whether any of them
          reflect back unencoded in the HTML response.

How it works:
  - Appends a short probe  "><'`  to each parameter value, one at a time
  - Sends ONE request per parameter (replaces only that param, others unchanged)
  - Checks the response for unencoded reflected probe characters
  - Reports WHICH characters reflected and in what HTML context
  - Deduplicates: same (host, path, param) is never tested twice
  - Only runs on responses whose original Content-Type was text/html
  - Also tests GET->POST and POST->GET method swap on each endpoint (once)

Probe string used:  xssP"><'`
  - Prefix "xssP" makes it easy to grep in the response
  - No full payload -- just chars to see what the server encodes/reflects

Installation:
  1. Extender -> Extensions -> Add -> Extension type: Python
  2. Select this file
  3. Use Burp Scanner (right-click -> Actively scan) OR
     just browse normally -- the extension hooks doActiveScan insertion points
"""

from burp import (IBurpExtender, IScannerCheck, IScanIssue, ITab,
                  IContextMenuFactory)
from javax.swing import (JPanel, JScrollPane, JTextArea, JLabel, JButton,
                         JMenuItem)
from java.awt import BorderLayout, Font, Color, Dimension
import re
import urllib

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXTENSION_NAME = "XSS Char Probe"
VERSION        = "2.1"

# Probe string: unique prefix + all special chars we want to test
PROBE_PREFIX   = "xssP"
PROBE_CHARS    = ['<', '>', '"', "'", '`']
PROBE_STRING   = PROBE_PREFIX + ''.join(PROBE_CHARS)   # xssP><"'`

# All known encoded forms for each special char.
# If the char appears in ANY of these forms after the probe prefix,
# it is considered encoded and NOT flagged as a finding.
#
# Covers:
#   HTML entities   : &lt;  &gt;  &quot;  &apos;
#   Decimal entities: &#60; &#34; &#39;
#   Hex entities    : &#x3c; &#x22; &#x27;
#   URL encoding    : %3C  %3E  %22  %27  %60
#   Double URL enc  : %253C %253E %2522 %2527 %2560
#   JS hex escapes  : \x3c \x3e \x22 \x27 \x60
#   JS unicode esc  : \u003c \u003e \u0022 \u0027
#   JS octal        : \74 \76
#   Backslash escape: \'  \"  (common in JS strings)
ENCODED_FORMS = {
    '<': [
        # HTML entities
        '&lt;', '&#60;', '&#x3c;', '&#x3C;', '&#X3c;', '&#X3C;',
        # URL encoding
        '%3c', '%3C',
        # Double URL encoding
        '%253c', '%253C',
        # JS hex / unicode escapes
        '\\x3c', '\\x3C',
        '\\u003c', '\\u003C',
        # JS octal
        '\\74',
        # JSON unicode-escaped HTML entity e.g. \u0026lt; (\u0026 = &)
        '\\u0026lt;', '\\u0026#60;',
    ],
    '>': [
        '&gt;', '&#62;', '&#x3e;', '&#x3E;', '&#X3e;', '&#X3E;',
        '%3e', '%3E',
        '%253e', '%253E',
        '\\x3e', '\\x3E',
        '\\u003e', '\\u003E',
        '\\76',
        '\\u0026gt;', '\\u0026#62;',
    ],
    '"': [
        '&quot;', '&#34;', '&#x22;', '&#X22;',
        '%22',
        '%2522',
        '\\x22',
        '\\u0022',
        '\\"',
        '\\u0026quot;',
    ],
    "'": [
        '&apos;', '&#39;', '&#x27;', '&#X27;',
        '%27',
        '%2527',
        '\\x27',
        '\\u0027',
        "\\'",
        '\\u0026apos;', '\\u0026#39;',
    ],
    # Backtick: no standard HTML encoding exists.
    # A raw ` is only dangerous inside JS template literals.
    # We deliberately keep this list short -- the real protection is
    # the _is_dangerous_reflection() check below which requires at least
    # one of < > " ' to also be unencoded before flagging backtick alone.
    '`': [
        '&#96;', '&#x60;', '&#X60;',
        '%60',
        '%2560',
        '\\x60',
        '\\u0060',
    ],
}

# Chars that are dangerous on their own (can break HTML / attributes).
# A raw backtick alone is NOT sufficient to flag a finding -- it needs
# at least one of these to also be unencoded.
DANGEROUS_CHARS = set(['<', '>', '"', "'"])

# ---------------------------------------------------------------------------
# Noise filters -- reduce clutter from tracking/analytics traffic
# ---------------------------------------------------------------------------

# Parameter names to skip entirely -- never user-controlled, never interesting
SKIP_PARAMS = set([
    # ASP.NET internals
    '__viewstate', '__eventvalidation', '__eventtarget', '__eventargument',
    '__viewstategenerator', '__scrollpositionx', '__scrollpositiony',
    '__previouspage', '__viewstateencrypted',
    # Google Analytics / Ads tracking
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
    'utm_id', 'utm_referrer',
    'gclid', 'gbraid', 'wbraid', 'gad_source', 'gad_campaignid',
    'gclgs', 'gclst', 'gcllp', 'gclaw', 'gclaw_src', 'gac',
    'cq_cmp', 'cq_med', 'cq_net', 'cq_plac', 'cq_plt',
    # Google Tag Manager / gtag internals
    'gtm', 'gtag', 'tid', 'en', 'dl', 'dp', 'dt', 'dr',
    # Consent / privacy
    'gdpr', 'gdpr_consent', 'us_privacy', 'gpp', 'gpp_s', 'gpp_as',
    'tcfe', 'npa', 'dma',
    # Ad / conversion pixels
    'cv', 'fst', 'bg', 'guid', 'async', 'capi', 'frm', 'fmt',
    'tiba', 'hn', 'label', 'value', 'auid', 'uaa', 'uab', 'uafvl',
    'uamb', 'uam', 'uap', 'uapv', 'uaw', 'ec_mode', 'random', 'rnd',
    'ipr', 'pscrd', 'fsk', 'crd', 'cerd', 'eitems', 'cid', 'is_vtc',
    'pscrd', 'ezwbk', 'pscdl', 'gcs', 'gcd', 'tag_exp',
    # Generic noise
    'ref', 'ver', 'version', 'v', 'cb', 'ts', 'timestamp', 'nonce',
    't', 'dt', 'dpr', 'biw', 'bih', 'ei', 'opi', 'atyp',
    'sa', 'ved', 'nis', 'pf', 'co', 'ase', 'sig', 'cce', 'category',
])

# Third-party / tracking domains to skip probing and method-swap entirely
SKIP_DOMAINS = [
    'google-analytics.com',
    'googletagmanager.com',
    'googleadservices.com',
    'doubleclick.net',
    'googlesyndication.com',
    'google.co.',         # google.co.in, google.co.uk etc
    'google.com/pagead',  # checked via path prefix
    'google.com/aclk',
    'google.com/client_204',
    'google.com/url',
    'googleapis.com',
    'gstatic.com',
    'facebook.com/tr',
    'facebook.net',
    'twitter.com/i/',
    'analytics.',
    'liadm.com',
    'bing.com/action',
    'bat.bing.com',
    'cdn.',
    'fonts.',
    'gravatar.com',
    'wp.com/i/',
    'cloudflare.com',
    'akamai',
]


class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        # Dedup stores
        self._seen_params   = set()   # (host, path, param_name)
        self._seen_methods  = set()   # (host, path) for method-swap test

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        self._tab = XSSTab(self)
        callbacks.addSuiteTab(self._tab)

        self._log("[ {} v{} loaded ]".format(EXTENSION_NAME, VERSION))
        self._log("Probe string: {}".format(PROBE_STRING))
        self._log("Only scanning Content-Type: text/html responses.")
        self._log("Right-click any request -> 'Re-scan with XSS Char Probe' to force re-scan")
        self._log("-" * 60)

    # -----------------------------------------------------------------------
    # IContextMenuFactory -- adds right-click menu in Burp
    # -----------------------------------------------------------------------
    def createMenuItems(self, invocation):
        menu_items = []
        selected = invocation.getSelectedMessages()
        if selected and len(selected) > 0:
            item = JMenuItem("Re-scan with XSS Char Probe")
            def action(event, msgs=selected):
                self._force_rescan(msgs)
            item.addActionListener(lambda e: action(e))
            menu_items.append(item)
        return menu_items

    def _force_rescan(self, messages):
        """
        Force re-scan of selected request(s), bypassing the dedup cache.
        Called from the right-click context menu.
        """
        for msg in messages:
            try:
                req_info = self._helpers.analyzeRequest(msg)
                url      = req_info.getUrl()
                host     = url.getHost()
                path     = url.getPath()

                # Clear dedup entries for this request so doPassiveScan re-runs
                # all params and method swap from scratch
                params = [p for p in req_info.getParameters()
                          if p.getType() in (0, 1)]
                for p in params:
                    self._seen_params.discard((host, path, p.getName()))
                self._seen_methods.discard((host, path))

                self._log("[Rescan] Cleared cache for {} -- running scan now".format(url))

                # Trigger the scan manually
                issues = self.doPassiveScan(msg)
                self._log("[Rescan] Done -- {} issues reported".format(len(issues)))
            except Exception as e:
                self._log("[ERROR] Rescan failed: {}".format(str(e)))

    # -----------------------------------------------------------------------
    # IScannerCheck - active scan insertion point
    # Called by Burp for each insertion point when active scanning.
    # We ignore the insertion point and do our own per-param probing.
    # -----------------------------------------------------------------------
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return []   # we handle everything in doPassiveScan-style below

    # -----------------------------------------------------------------------
    # IScannerCheck - passive scan hook
    # We use this to intercept every proxied request and run our char probes.
    # -----------------------------------------------------------------------
    def doPassiveScan(self, baseRequestResponse):
        issues = []
        try:
            request  = baseRequestResponse.getRequest()
            response = baseRequestResponse.getResponse()
            if request is None or response is None:
                return issues

            req_info  = self._helpers.analyzeRequest(baseRequestResponse)
            resp_info = self._helpers.analyzeResponse(response)

            # ----------------------------------------------------------------
            # Only probe endpoints that originally returned text/html
            # ----------------------------------------------------------------
            if not self._is_html_response(response):
                return issues

            url    = req_info.getUrl()
            host   = url.getHost()
            path   = url.getPath()
            method = req_info.getMethod().upper()
            http_service = baseRequestResponse.getHttpService()

            # ----------------------------------------------------------------
            # Skip known tracking / analytics / ad domains entirely
            # ----------------------------------------------------------------
            if self._is_noisy_target(host, path):
                return issues

            params = [p for p in req_info.getParameters()
                      if p.getType() in (0, 1)
                      and not self._should_skip_param(p.getName())]

            # Skip if no interesting params remain after filtering
            if not params:
                return issues

            # ----------------------------------------------------------------
            # Per-parameter probe
            # ----------------------------------------------------------------
            for param in params:
                param_name = param.getName()
                dedup_key  = (host, path, param_name)

                if dedup_key in self._seen_params:
                    continue
                self._seen_params.add(dedup_key)

                # Build a new request with probe injected into this param only
                probe_request = self._build_probe_request(
                    request, req_info, param, PROBE_STRING)
                if probe_request is None:
                    continue

                # Send the probe request
                probe_response = self._callbacks.makeHttpRequest(
                    http_service, probe_request)
                if probe_response is None:
                    self._log("[WARN] No probe response | {} param={}".format(
                        url, param_name))
                    continue

                probe_resp_bytes = probe_response.getResponse()
                if probe_resp_bytes is None:
                    self._log("[WARN] Probe response empty | {} param={}".format(
                        url, param_name))
                    continue

                probe_resp_info = self._helpers.analyzeResponse(probe_resp_bytes)
                probe_body = self._helpers.bytesToString(
                    probe_resp_bytes[probe_resp_info.getBodyOffset():])

                # Diagnostic: was probe prefix even in the response?
                probe_found = PROBE_PREFIX in probe_body

                # Check which chars reflected unencoded
                reflected_chars, context = self._check_probe_reflection(
                    probe_body, param.getValue())

                if reflected_chars:
                    severity = self._get_severity(reflected_chars)
                    detail   = self._build_detail(
                        url, param_name, method, reflected_chars, context,
                        PROBE_STRING)
                    issues.append(XSSIssue(
                        probe_response, url,
                        "[XSS Probe] Special Chars Reflected Unencoded",
                        detail, severity, "Firm"
                    ))
                    self._log("[{}] {} | param={} | reflected: {} | ctx={}".format(
                        severity, url, param_name,
                        ', '.join(reflected_chars), context))
                elif not probe_found:
                    # Probe was filtered/stripped by server -- worth noting
                    self._log("[Filtered] {} | param={} | probe not in response".format(
                        url, param_name))

            # ----------------------------------------------------------------
            # Method-swap test (once per endpoint)
            # ----------------------------------------------------------------
            method_key = (host, path)
            if method_key not in self._seen_methods:
                self._seen_methods.add(method_key)
                swap_issues = self._test_method_swap(
                    baseRequestResponse, req_info, http_service, url)
                issues.extend(swap_issues)

        except Exception as e:
            self._log("[ERROR] doPassiveScan: {}".format(str(e)))

        return issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if (existingIssue.getIssueName() == newIssue.getIssueName()
                and str(existingIssue.getUrl()) == str(newIssue.getUrl())):
            return -1
        return 0

    # -----------------------------------------------------------------------
    # Core helpers
    # -----------------------------------------------------------------------

    def _is_html_response(self, response):
        """
        Return True only if the response has Content-Type: text/html.
        Reads the raw header -- not Burp's inferred MIME.
        """
        try:
            headers = self._helpers.analyzeResponse(response).getHeaders()
            for h in headers:
                if h.lower().startswith('content-type:'):
                    return 'text/html' in h.lower()
        except Exception:
            pass
        return False

    def _is_noisy_target(self, host, path):
        """
        Return True if this host+path is a known tracking/analytics endpoint
        that should be skipped entirely (no probing, no method swap).
        """
        target = (host + path).lower()
        for pattern in SKIP_DOMAINS:
            if pattern in target:
                return True
        return False

    def _should_skip_param(self, name):
        """
        Return True if this parameter name is in the skip list --
        internal ASP.NET tokens, tracking params, ad pixels etc.
        """
        return name.lower() in SKIP_PARAMS

    def _is_base64_value(self, value):
        """
        Return True if the parameter value looks like a base64-encoded string
        or a JWT (which contains base64 segments separated by dots).
        These values should not be replaced -- probe is appended after them.
        """
        if len(value) < 16:
            return False
        # JWT: three base64url segments separated by dots
        if value.count('.') == 2:
            parts = value.split('.')
            b64url = re.compile(r'^[A-Za-z0-9_\-]+=*$')
            if all(b64url.match(p) for p in parts if p):
                return True
        # Standard and URL-safe base64 (no dots)
        b64_re = re.compile(r'^[A-Za-z0-9+/=_\-]{16,}$')
        return bool(b64_re.match(value))

    def _build_probe_request(self, request, req_info, param, probe_value):
        """
        Build a probe request by injecting the probe string into the parameter.

        For normal params:
          Replace the value entirely with the probe.
          e.g. q=hello  ->  q=xssP%3C%3E%22%27%60

        For base64-looking params:
          Append the probe AFTER the base64 value using a raw delimiter.
          The base64 value is kept intact so the server can decode it,
          then the probe chars break out of whatever context the value
          lands in.
          e.g. encodedParams=bG9naW5Q  ->  encodedParams=bG9naW5Q%22%3ExssP%3C%3E%22%27%60
          The " and > before xssP attempt to break out of the HTML context
          before the probe prefix, maximising the chance xssP survives.
        """
        try:
            original_value = param.getValue()

            if self._is_base64_value(original_value):
                # For base64 params inject breakout chars RAW (not URL-encoded)
                # so the server sees literal " > that break the HTML context.
                # We do a raw string replacement in the request bytes to avoid
                # Burp's updateParameter URL-encoding the breakout chars.
                encoded_probe = urllib.quote(probe_value, safe='')
                # Final injected value: base64value + raw "> + url-encoded probe
                # e.g. bG9naW5Q">xssP%3C%3E%22%27%60
                injected_value = original_value + '">' + encoded_probe

                raw_request = self._helpers.bytesToString(request)

                # Try to find and replace the exact value as it appears in request
                # Could be URL-encoded or raw depending on how Burp parsed it
                url_encoded_orig = urllib.quote(original_value, safe='')

                if url_encoded_orig in raw_request:
                    new_raw = raw_request.replace(
                        url_encoded_orig, injected_value, 1)
                elif original_value in raw_request:
                    new_raw = raw_request.replace(
                        original_value, injected_value, 1)
                else:
                    # Cannot locate value in raw request -- fall back to normal probe
                    encoded_probe2 = urllib.quote(probe_value, safe='')
                    return self._helpers.updateParameter(
                        request,
                        self._helpers.buildParameter(
                            param.getName(), encoded_probe2, param.getType()))

                new_request = self._helpers.stringToBytes(new_raw)
                self._log("[b64] {} -- raw breakout injection".format(
                    param.getName()))
            else:
                # Normal param: replace value with probe
                encoded_probe = urllib.quote(probe_value, safe='')
                new_request = self._helpers.updateParameter(
                    request,
                    self._helpers.buildParameter(
                        param.getName(),
                        encoded_probe,
                        param.getType()
                    )
                )
            return new_request

        except Exception as e:
            self._log("[WARN] Could not build probe request: {}".format(str(e)))
            return None

    def _check_probe_reflection(self, body, original_value=None):
        """
        Check ALL occurrences of PROBE_PREFIX in the response body.
        A page may reflect the same value multiple times in different contexts:
        one place may HTML-encode it (safe), another may reflect it raw (XSS).
        We return the WORST case -- the occurrence with the most unencoded chars.

        For each xssP occurrence:
          1. Check chars immediately after for raw vs encoded
          2. For base64 params, also check breakout chars `">` before xssP

        Returns the union of all dangerous chars found across occurrences.
        """
        reflected = []
        context   = 'unknown'

        # Find ALL positions of xssP, not just the first
        all_positions = []
        pos = 0
        while True:
            idx = body.find(PROBE_PREFIX, pos)
            if idx == -1:
                break
            all_positions.append(idx)
            pos = idx + 1

        if not all_positions:
            return reflected, context

        # Track best (most dangerous) reflection
        best_chars   = []
        best_context = 'unknown'

        for probe_idx in all_positions:
            occurrence_chars = []
            occurrence_ctx   = self._determine_context(body, probe_idx)

            after_prefix = body[probe_idx + len(PROBE_PREFIX):]
            after_lower  = after_prefix.lower()

            # Check chars AFTER xssP at this occurrence
            for ch in PROBE_CHARS:
                raw_pos = after_prefix.find(ch)
                if raw_pos == -1:
                    continue
                # Stop searching after we hit a non-probe char (likely end of value)
                # so we don't pick up encoded forms from elsewhere on the page
                search_window = after_lower[:min(raw_pos + 20, 30)]
                safe_forms    = list(ENCODED_FORMS.get(ch, []))
                if occurrence_ctx == 'js_string':
                    if ch == '"':   safe_forms.append('\\"')
                    elif ch == "'": safe_forms.append("\\'")
                if any(enc.lower() in search_window for enc in safe_forms):
                    continue
                occurrence_chars.append(ch)

            # Check breakout chars BEFORE xssP (base64 path)
            if original_value and self._is_base64_value(original_value):
                before_window = body[max(0, probe_idx - 5):probe_idx]
                for ch in ['"', '>']:
                    if ch in before_window and ch not in occurrence_chars:
                        if not any(enc.lower() in before_window.lower()
                                   for enc in ENCODED_FORMS.get(ch, [])):
                            occurrence_chars.append(ch)
                            occurrence_ctx = 'html_attr'

            # Drop backtick-only occurrences
            if occurrence_chars == ['`']:
                occurrence_chars = []

            # Keep the most dangerous occurrence
            # Prioritise occurrences with < or > (highest XSS impact)
            occurrence_score = (
                ('<' in occurrence_chars or '>' in occurrence_chars) * 100
                + ('"' in occurrence_chars or "'" in occurrence_chars) * 10
                + len(occurrence_chars)
            )
            best_score = (
                ('<' in best_chars or '>' in best_chars) * 100
                + ('"' in best_chars or "'" in best_chars) * 10
                + len(best_chars)
            )
            if occurrence_score > best_score:
                best_chars   = occurrence_chars
                best_context = occurrence_ctx

        return best_chars, best_context








    def _determine_context(self, body, probe_idx):
        """
        Determine the rendering context at probe_idx by walking backwards
        through the response to find what HTML/JS structure surrounds it.

        Priority order (most specific first):
          1. Inside a <script> block           -> js_string
          2. Inside an HTML attribute value    -> html_attr
          3. Inside an open HTML tag (no attr) -> html_tag
          4. Inside an HTML text node          -> html_text
          5. Unknown

        Key fix: JS string detection ONLY triggers inside <script> blocks.
        A pattern like href="VALUE" must not be mistaken for a JS assignment.
        """
        snippet = body[max(0, probe_idx - 500): probe_idx]

        # ---- 1. Are we inside a <script> block? ----
        # Find the last <script and last </script before the probe
        last_script_open  = snippet.lower().rfind('<script')
        last_script_close = snippet.lower().rfind('</script')
        in_script = (last_script_open != -1
                     and last_script_open > last_script_close)

        if in_script:
            # Inside <script> -- check if we are inside a string literal
            script_content = snippet[last_script_open:]
            # Count unescaped double and single quotes to determine string state
            in_dq = (script_content.count('"') -
                     script_content.count('\\"')) % 2 == 1
            in_sq = (script_content.count("'") -
                     script_content.count("\\'")) % 2 == 1
            if in_dq or in_sq:
                return 'js_string'
            return 'js_string'  # in script but not in a string -- still JS

        # ---- 2. Are we inside an HTML tag? ----
        # Find the last unclosed < before the probe
        last_open_tag  = snippet.rfind('<')
        last_close_tag = snippet.rfind('>')

        if last_open_tag > last_close_tag:
            # We are inside an open tag -- is it inside an attribute value?
            tag_content = snippet[last_open_tag:]

            # Check for attribute = "VALUE or = 'VALUE (unclosed)
            # Match: word chars, optional space, =, then quote, then no closing quote
            dq_attr = re.search(r'\s[\w\-]+=\s*"[^"]*$', tag_content)
            sq_attr = re.search(r"\s[\w\-]+=\s*'[^']*$", tag_content)
            uq_attr = re.search(r'\s[\w\-]+=\s*[^"\'\s>]+$', tag_content)

            if dq_attr or sq_attr or uq_attr:
                return 'html_attr'
            return 'html_tag'

        # ---- 3. HTML text node (between tags) ----
        if last_close_tag != -1:
            return 'html_text'

        return 'unknown'


    def _get_severity(self, reflected_chars):
        """
        High  : < or > reflected (can open/close tags)
        Medium: " or ' reflected (can break out of attributes)
        Low   : only ` reflected
        """
        if '<' in reflected_chars or '>' in reflected_chars:
            return "High"
        if '"' in reflected_chars or "'" in reflected_chars:
            return "Medium"
        return "Low"

    def _get_original_headers(self, req_info):
        """
        Extract headers from the original request that should be carried
        over to the swapped request: Host, Cookie, User-Agent, Accept,
        Accept-Language, Referer, Authorization, and any X- headers.

        Strips Content-Type and Content-Length (caller sets these).
        Strips the request line (first header).
        Returns a list of header strings ready for buildHttpMessage().
        """
        skip_prefixes = (
            'content-type:', 'content-length:',
            'transfer-encoding:', 'connection:'
        )
        headers = req_info.getHeaders()
        result  = []
        for i, h in enumerate(headers):
            if i == 0:
                # Skip the original request line (GET /path HTTP/1.1)
                continue
            if h.lower().startswith(skip_prefixes):
                continue
            result.append(h)
        # Always ensure Connection: close is present
        result.append("Connection: close")
        return result

    def _test_method_swap(self, brr, req_info, http_service, url):
        """
        1. Build the swapped request (GET->POST or POST->GET)
        2. Send it once to check if the endpoint accepts the swapped method
        3. If accepted (HTTP 200 + text/html), run the full XSS char probe
           on every parameter in the swapped request -- same probe logic
           used for the original method
        """
        issues  = []
        method  = req_info.getMethod().upper()
        params  = list(req_info.getParameters())

        query_params = [p for p in params if p.getType() == 0]  # URL params
        body_params  = [p for p in params if p.getType() == 1]  # Body params

        try:
            # ----------------------------------------------------------------
            # Build the swapped base request (no probe yet, original values)
            # ----------------------------------------------------------------
            if method == "GET" and query_params:
                swap_label     = "GET-to-POST"
                swapped_params = [p for p in query_params
                                  if not self._should_skip_param(p.getName())]
                if not swapped_params:
                    return issues

                base_body = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in query_params
                )
                # Carry original headers (Host, Cookie, User-Agent etc.)
                # but replace the request line and add Content-Type/Length
                orig_headers = self._get_original_headers(req_info)
                base_headers = (
                    ["POST {} HTTP/1.1".format(url.getPath())]
                    + orig_headers
                    + [
                        "Content-Type: application/x-www-form-urlencoded",
                        "Content-Length: {}".format(len(base_body)),
                    ]
                )
                base_swapped_request = self._helpers.buildHttpMessage(
                    base_headers, self._helpers.stringToBytes(base_body))

            elif method == "POST" and body_params:
                swap_label     = "POST-to-GET"
                swapped_params = [p for p in body_params
                                  if not self._should_skip_param(p.getName())]
                if not swapped_params:
                    return issues

                qs = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in body_params
                )
                orig_headers = self._get_original_headers(req_info)
                base_headers = (
                    ["GET {}?{} HTTP/1.1".format(url.getPath(), qs)]
                    + orig_headers
                )
                base_swapped_request = self._helpers.buildHttpMessage(
                    base_headers, None)
            else:
                return issues

            # ----------------------------------------------------------------
            # Step 1: Send base swapped request to check if method is accepted
            # ----------------------------------------------------------------
            base_swap_resp = self._callbacks.makeHttpRequest(
                http_service, base_swapped_request)
            if base_swap_resp is None:
                return issues

            base_resp_bytes = base_swap_resp.getResponse()
            if base_resp_bytes is None:
                return issues

            base_resp_info = self._helpers.analyzeResponse(base_resp_bytes)
            status_code    = base_resp_info.getStatusCode()

            self._log("[MethodSwap] {} | {} | status={}".format(
                swap_label, url, status_code))

            # Only continue probing if the swap was accepted with HTML response
            if status_code != 200 or not self._is_html_response(base_resp_bytes):
                if status_code != 200:
                    detail = (
                        "Method swap <b>{}</b> on <b>{}</b> returned HTTP {}. "
                        "Endpoint does not appear to accept the swapped method."
                    ).format(swap_label, url, status_code)
                    issues.append(XSSIssue(
                        base_swap_resp, url,
                        "[XSS Probe] Method Swap Rejected ({})".format(swap_label),
                        detail, "Information", "Certain"
                    ))
                return issues

            # ----------------------------------------------------------------
            # Step 2: Method accepted -- report it
            # ----------------------------------------------------------------
            issues.append(XSSIssue(
                base_swap_resp, url,
                "[XSS Probe] Method Swap Accepted ({})".format(swap_label),
                (
                    "Method swap <b>{}</b> on <b>{}</b> returned HTTP 200.<br><br>"
                    "The endpoint accepts both methods. This may indicate:<br>"
                    "- Missing method-specific input validation<br>"
                    "- WAF rules that only cover one method<br>"
                    "- CSRF protections tied to POST only<br><br>"
                    "Now probing all parameters via the swapped method..."
                ).format(swap_label, url),
                "Information", "Certain"
            ))

            # ----------------------------------------------------------------
            # Step 3: Probe each parameter via the swapped method
            # One request per param, inject PROBE_STRING, check reflection
            # ----------------------------------------------------------------
            for param in swapped_params:
                param_name = param.getName()
                dedup_key  = (url.getHost(), url.getPath(),
                              param_name + "_" + swap_label)

                if dedup_key in self._seen_params:
                    continue
                self._seen_params.add(dedup_key)

                encoded_probe = urllib.quote(PROBE_STRING, safe='')

                # Build probed swapped request for this param
                # Re-use orig_headers so cookies are always included
                if swap_label == "GET-to-POST":
                    probe_body = '&'.join(
                        "{}={}".format(
                            urllib.quote(p.getName(), safe=''),
                            encoded_probe if p.getName() == param_name
                            else urllib.quote(p.getValue(), safe=''))
                        for p in swapped_params
                    )
                    probe_headers = (
                        ["POST {} HTTP/1.1".format(url.getPath())]
                        + orig_headers
                        + [
                            "Content-Type: application/x-www-form-urlencoded",
                            "Content-Length: {}".format(len(probe_body)),
                        ]
                    )
                    probe_request = self._helpers.buildHttpMessage(
                        probe_headers,
                        self._helpers.stringToBytes(probe_body))

                else:
                    probe_qs = '&'.join(
                        "{}={}".format(
                            urllib.quote(p.getName(), safe=''),
                            encoded_probe if p.getName() == param_name
                            else urllib.quote(p.getValue(), safe=''))
                        for p in swapped_params
                    )
                    probe_headers = (
                        ["GET {}?{} HTTP/1.1".format(url.getPath(), probe_qs)]
                        + orig_headers
                    )
                    probe_request = self._helpers.buildHttpMessage(
                        probe_headers, None)

                probe_resp = self._callbacks.makeHttpRequest(
                    http_service, probe_request)
                if probe_resp is None:
                    continue

                probe_resp_bytes = probe_resp.getResponse()
                if probe_resp_bytes is None:
                    continue

                probe_resp_info = self._helpers.analyzeResponse(probe_resp_bytes)
                probe_body_str  = self._helpers.bytesToString(
                    probe_resp_bytes[probe_resp_info.getBodyOffset():])

                reflected_chars, context = self._check_probe_reflection(
                    probe_body_str, param.getValue())

                if reflected_chars:
                    severity = self._get_severity(reflected_chars)
                    detail   = self._build_detail(
                        url, param_name,
                        "POST (swapped)" if swap_label == "GET-to-POST" else "GET (swapped)",
                        reflected_chars, context, PROBE_STRING)
                    issues.append(XSSIssue(
                        probe_resp, url,
                        "[XSS Probe] Special Chars Reflected via {} -- param: {}".format(
                            swap_label, param_name),
                        detail, severity, "Firm"
                    ))
                    self._log("[{}][{}] {} | param={} | reflected: {} | ctx={}".format(
                        severity, swap_label, url, param_name,
                        ', '.join(reflected_chars), context))

        except Exception as e:
            self._log("[WARN] Method swap failed: {}".format(str(e)))

        return issues

    def _build_detail(self, url, param, method, reflected_chars, context, probe):
        char_list = ', '.join(
            "<b>{}</b>".format(ch) for ch in reflected_chars)
        ctx_advice = {
            'html_attr':  "Char reflected inside an HTML attribute. "
                          "Breaking out of the attribute may allow event handler injection "
                          "e.g. \" onmouseover=alert(1) x=\"",
            'html_tag':   "Char reflected inside an HTML tag. "
                          "May allow injecting new attributes e.g. onload=alert(1)",
            'js_string':  "Char reflected inside a JavaScript string. "
                          "Breaking out does not require < or > e.g. ';alert(1)//",
            'html_text':  "Char reflected in HTML text node. "
                          "Can inject full tags e.g. <script>alert(1)</script>",
            'unknown':    "Context could not be determined. Manual review recommended.",
        }.get(context, "Unknown context.")

        return (
            "Parameter <b>{}</b> on <b>{}</b> ({}) reflects special "
            "characters unencoded.<br><br>"
            "Probe sent: <code>{}</code><br>"
            "Characters reflected unencoded: {}<br>"
            "Detected context: <b>{}</b><br><br>"
            "{}<br><br>"
            "This is an indicator of potential XSS -- manual verification "
            "with a full payload is required to confirm exploitability."
        ).format(param, url, method, probe, char_list, context, ctx_advice)

    def _log(self, msg):
        if hasattr(self, '_tab'):
            self._tab.append(msg)


# ---------------------------------------------------------------------------
# Swing UI Tab -- colored log using JTextPane + StyledDocument
# ---------------------------------------------------------------------------
class XSSTab(ITab):

    def __init__(self, extender):
        self._extender = extender
        self._panel    = JPanel(BorderLayout())

        header = JLabel(
            "  {} v{}  --  XSS Special Char Probe (text/html only)".format(
                EXTENSION_NAME, VERSION))
        header.setFont(Font("Monospaced", Font.BOLD, 13))
        header.setForeground(Color(220, 80, 80))

        # JTextPane supports per-line colors via StyledDocument
        from javax.swing import JTextPane
        from javax.swing.text import SimpleAttributeSet, StyleConstants
        from java.awt import Color as JColor

        self._text_pane = JTextPane()
        self._text_pane.setEditable(False)
        self._text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._text_pane.setBackground(Color(18, 18, 18))

        # Store imports for use in append()
        self._SimpleAttributeSet = SimpleAttributeSet
        self._StyleConstants      = StyleConstants

        # Pre-build named styles
        self._styles = {}
        color_map = {
            'high':   JColor(255,  80,  80),   # red
            'medium': JColor(255, 180,  50),   # orange
            'low':    JColor(255, 230, 100),   # yellow
            'swap':   JColor(100, 180, 255),   # blue
            'info':   JColor(160, 255, 160),   # green (default)
            'error':  JColor(255,  60,  60),   # bright red
        }
        for name, color in color_map.items():
            style = SimpleAttributeSet()
            StyleConstants.setForeground(style, color)
            StyleConstants.setFontFamily(style, "Monospaced")
            StyleConstants.setFontSize(style, 12)
            self._styles[name] = style

        scroll = JScrollPane(self._text_pane)
        scroll.setPreferredSize(Dimension(900, 600))

        clear_btn = JButton("Clear Log + Reset Dedup Cache")
        clear_btn.addActionListener(lambda e: self._clear())

        self._panel.add(header,    BorderLayout.NORTH)
        self._panel.add(scroll,    BorderLayout.CENTER)
        self._panel.add(clear_btn, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "XSS Probe"

    def getUiComponent(self):
        return self._panel

    def append(self, msg):
        """
        Append a colored line based on severity prefix in the message.
        [High]   -> red
        [Medium] -> orange
        [Low]    -> yellow
        [MethodSwap] / [GET-to-POST] / [POST-to-GET] -> blue
        [ERROR]  -> bright red
        default  -> green
        """
        msg_lower = msg.lower()
        if '[high]' in msg_lower or '[error]' in msg_lower:
            style_key = 'high' if '[high]' in msg_lower else 'error'
        elif '[medium]' in msg_lower:
            style_key = 'medium'
        elif '[low]' in msg_lower:
            style_key = 'low'
        elif any(x in msg_lower for x in ['[methodswap]', '[get-to-post]',
                                           '[post-to-get]', 'swap']):
            style_key = 'swap'
        else:
            style_key = 'info'

        style = self._styles[style_key]
        doc   = self._text_pane.getStyledDocument()
        try:
            doc.insertString(doc.getLength(), msg + "\n", style)
        except Exception:
            pass
        self._text_pane.setCaretPosition(doc.getLength())

    def _clear(self):
        self._text_pane.setText("")
        self._extender._seen_params.clear()
        self._extender._seen_methods.clear()
        self.append("[ Log cleared -- dedup cache reset ]")


# ---------------------------------------------------------------------------
# IScanIssue implementation
# ---------------------------------------------------------------------------
class XSSIssue(IScanIssue):

    def __init__(self, brr, url, name, detail, severity, confidence):
        self._brr        = brr
        self._url        = url
        self._name       = name
        self._detail     = detail
        self._severity   = severity
        self._confidence = confidence

    def getUrl(self):               return self._url
    def getIssueName(self):         return self._name
    def getIssueType(self):         return 0x08000000
    def getSeverity(self):          return self._severity
    def getConfidence(self):        return self._confidence
    def getIssueDetail(self):       return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self):      return [self._brr]
    def getHttpService(self):       return self._brr.getHttpService()

    def getIssueBackground(self):
        return (
            "Special characters such as < > \" ' ` are the building blocks "
            "of XSS. If the server reflects them unencoded, a full XSS "
            "payload may be possible depending on the injection context."
        )

    def getRemediationBackground(self):
        return (
            "HTML-encode all user-supplied output. Apply context-aware encoding "
            "(HTML, attribute, JS). Use Content-Security-Policy headers."
        )
