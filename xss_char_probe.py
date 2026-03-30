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

from burp import IBurpExtender, IScannerCheck, IScanIssue, ITab
from javax.swing import JPanel, JScrollPane, JTextArea, JLabel, JButton
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
        '&lt;', '&#60;', '&#x3c;', '&#x3C;', '&#X3c;', '&#X3C;',
        '%3c', '%3C',
        '%253c', '%253C',
        '\\x3c', '\\x3C',
        '\\u003c', '\\u003C',
        '\\74',
    ],
    '>': [
        '&gt;', '&#62;', '&#x3e;', '&#x3E;', '&#X3e;', '&#X3E;',
        '%3e', '%3E',
        '%253e', '%253E',
        '\\x3e', '\\x3E',
        '\\u003e', '\\u003E',
        '\\76',
    ],
    '"': [
        '&quot;', '&#34;', '&#x22;', '&#X22;',
        '%22',
        '%2522',
        '\\x22',
        '\\u0022',
        '\\"',
    ],
    "'": [
        '&apos;', '&#39;', '&#x27;', '&#X27;',
        '%27',
        '%2527',
        '\\x27',
        '\\u0027',
        "\\'",
    ],
    '`': [
        '&#96;', '&#x60;', '&#X60;',
        '%60',
        '%2560',
        '\\x60',
        '\\u0060',
    ],
}

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


class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        # Dedup stores
        self._seen_params   = set()   # (host, path, param_name)
        self._seen_methods  = set()   # (host, path) for method-swap test

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(self)

        self._tab = XSSTab(self)
        callbacks.addSuiteTab(self._tab)

        self._log("[ {} v{} loaded ]".format(EXTENSION_NAME, VERSION))
        self._log("Probe string: {}".format(PROBE_STRING))
        self._log("Only scanning Content-Type: text/html responses.")
        self._log("-" * 60)

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
                    continue

                probe_resp_bytes = probe_response.getResponse()
                if probe_resp_bytes is None:
                    continue

                probe_resp_info = self._helpers.analyzeResponse(probe_resp_bytes)
                probe_body = self._helpers.bytesToString(
                    probe_resp_bytes[probe_resp_info.getBodyOffset():])

                # Check which chars reflected unencoded
                reflected_chars, context = self._check_probe_reflection(probe_body)

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

    def _build_probe_request(self, request, req_info, param, probe_value):
        """
        Return a new request byte array with the probe value injected into
        the given parameter.  All other parameters are left unchanged.
        """
        try:
            # URL-encode the probe for safe transport
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

    def _check_probe_reflection(self, body):
        """
        Search the response body for the probe prefix, then for each special
        char determine whether it is reflected in a DANGEROUS (unencoded) way.

        Context matters:
          - In a JS string context  : backslash-escaped \" or \' IS safe
                                      but raw < > are still dangerous
          - In HTML context         : only HTML entities / URL encoding are safe
          - In all contexts         : URL encoding and JS hex/unicode are safe

        Returns:
          reflected_chars : list of chars reflected dangerously e.g. ['<', '"']
          context         : 'html_attr'|'html_tag'|'js_string'|'html_text'|'unknown'
        """
        reflected = []
        context   = 'unknown'

        probe_idx = body.find(PROBE_PREFIX)
        if probe_idx == -1:
            return reflected, context

        # Determine context BEFORE checking chars so we can apply context rules
        context = self._determine_context(body, probe_idx)

        after_prefix = body[probe_idx + len(PROBE_PREFIX):]
        after_lower  = after_prefix.lower()

        for ch in PROBE_CHARS:
            raw_pos = after_prefix.find(ch)
            if raw_pos == -1:
                # Raw char not present at all -- safe (stripped or encoded)
                continue

            # Check the window just before and around the raw char position
            search_window = after_lower[:raw_pos + 20]

            # Build the safe encoding list for this char + context
            safe_forms = list(ENCODED_FORMS.get(ch, []))

            # In a JS string context, backslash escaping is safe ONLY for
            # the matching quote character:
            #   \" is safe for "  (server escaped the double quote)
            #   \' is safe for '  (server escaped the single quote)
            # Do NOT cross-add -- \" does not make ' safe and vice versa.
            if context == 'js_string':
                if ch == '"':
                    safe_forms.append('\\"')
                elif ch == "'":
                    safe_forms.append("\\'")

            is_encoded = any(
                enc.lower() in search_window
                for enc in safe_forms
            )

            if is_encoded:
                continue

            # Raw char present with no safe encoding around it -- flag it
            reflected.append(ch)

        return reflected, context



    def _determine_context(self, body, probe_idx):
        """
        Look at the characters before the probe position to guess the
        HTML/JS rendering context.

        Contexts:
          html_attr  -- inside an HTML attribute value  e.g. value="PROBE"
          html_tag   -- inside an HTML tag              e.g. <tag PROBE>
          js_string  -- inside a JavaScript string      e.g. var x = "PROBE"
          html_text  -- in normal HTML text node        e.g. <p>PROBE</p>
          unknown
        """
        snippet = body[max(0, probe_idx - 200): probe_idx]

        # JS string context -- look for var/let/const or = " or = '
        if re.search(r'(var|let|const)\s+\w+\s*=\s*["\']', snippet):
            return 'js_string'
        if re.search(r'=\s*["\'][^"\']*$', snippet):
            return 'js_string'

        # HTML attribute context -- inside a tag with an = sign
        if re.search(r'<[a-zA-Z][^>]*[\s][a-zA-Z\-]+=[\"\']?[^>]*$', snippet):
            return 'html_attr'

        # Inside an open HTML tag (no closing >)
        if re.search(r'<[a-zA-Z][^>]*$', snippet):
            return 'html_tag'

        # Default: HTML text node
        last_close = snippet.rfind('>')
        if last_close != -1:
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
                swap_label   = "GET-to-POST"
                swapped_params = query_params
                new_param_type = 1   # will inject as body params

                base_body = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in query_params
                )
                base_headers = [
                    "POST {} HTTP/1.1".format(url.getPath()),
                    "Host: {}".format(url.getHost()),
                    "Content-Type: application/x-www-form-urlencoded",
                    "Content-Length: {}".format(len(base_body)),
                    "Connection: close",
                ]
                base_swapped_request = self._helpers.buildHttpMessage(
                    base_headers, self._helpers.stringToBytes(base_body))

            elif method == "POST" and body_params:
                swap_label   = "POST-to-GET"
                swapped_params = body_params
                new_param_type = 0   # will inject as URL params

                qs = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in body_params
                )
                base_headers = [
                    "GET {}?{} HTTP/1.1".format(url.getPath(), qs),
                    "Host: {}".format(url.getHost()),
                    "Connection: close",
                ]
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
                if swap_label == "GET-to-POST":
                    # Rebuild POST body with probe in this param only
                    probe_body = '&'.join(
                        "{}={}".format(
                            urllib.quote(p.getName(), safe=''),
                            encoded_probe if p.getName() == param_name
                            else urllib.quote(p.getValue(), safe=''))
                        for p in swapped_params
                    )
                    probe_headers = [
                        "POST {} HTTP/1.1".format(url.getPath()),
                        "Host: {}".format(url.getHost()),
                        "Content-Type: application/x-www-form-urlencoded",
                        "Content-Length: {}".format(len(probe_body)),
                        "Connection: close",
                    ]
                    probe_request = self._helpers.buildHttpMessage(
                        probe_headers,
                        self._helpers.stringToBytes(probe_body))

                else:
                    # Rebuild GET query string with probe in this param only
                    probe_qs = '&'.join(
                        "{}={}".format(
                            urllib.quote(p.getName(), safe=''),
                            encoded_probe if p.getName() == param_name
                            else urllib.quote(p.getValue(), safe=''))
                        for p in swapped_params
                    )
                    probe_headers = [
                        "GET {}?{} HTTP/1.1".format(url.getPath(), probe_qs),
                        "Host: {}".format(url.getHost()),
                        "Connection: close",
                    ]
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
                    probe_body_str)

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
# Swing UI Tab
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

        self._log_area = JTextArea()
        self._log_area.setEditable(False)
        self._log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._log_area.setBackground(Color(18, 18, 18))
        self._log_area.setForeground(Color(160, 255, 160))
        self._log_area.setLineWrap(True)

        scroll = JScrollPane(self._log_area)
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
        self._log_area.append(msg + "\n")
        self._log_area.setCaretPosition(
            self._log_area.getDocument().getLength())

    def _clear(self):
        self._log_area.setText("")
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
