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
VERSION        = "2.0"

# Probe string: unique prefix + all special chars we want to test
PROBE_PREFIX   = "xssP"
PROBE_CHARS    = ['<', '>', '"', "'", '`']
PROBE_STRING   = PROBE_PREFIX + ''.join(PROBE_CHARS)   # xssP><"'`

# Map each char to its expected HTML-encoded form
ENCODED_FORMS  = {
    '<':  ['&lt;', '&#60;', '&#x3c;', '&#x3C;'],
    '>':  ['&gt;', '&#62;', '&#x3e;', '&#x3E;'],
    '"':  ['&quot;', '&#34;', '&#x22;'],
    "'":  ['&apos;', '&#39;', '&#x27;'],
    '`':  [],   # no standard HTML encoding for backtick
}

# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------
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

            params = [p for p in req_info.getParameters()
                      if p.getType() in (0, 1)]  # URL params and body params only

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
        Search the response body for the probe prefix, then check which
        special characters reflect back unencoded immediately after it.

        Returns:
          reflected_chars : list of chars that reflected unencoded e.g. ['<', '"']
          context         : 'html_attr', 'html_tag', 'js_string', 'html_text', 'unknown'
        """
        reflected = []
        context   = 'unknown'

        # Find where our probe prefix landed in the response
        probe_idx = body.find(PROBE_PREFIX)
        if probe_idx == -1:
            return reflected, context

        # Grab a window around the probe to check context and chars
        window_start = max(0, probe_idx - 100)
        window_end   = min(len(body), probe_idx + len(PROBE_STRING) + 50)
        window       = body[window_start:window_end]

        # Extract what came after the prefix
        after_prefix = body[probe_idx + len(PROBE_PREFIX):]

        # Check each special char
        for ch in PROBE_CHARS:
            # Check if the raw char appears right after the prefix
            # before any encoded form could appear
            char_pos = after_prefix.find(ch)
            if char_pos == -1:
                continue

            # Make sure it is NOT an encoded equivalent
            encoded = False
            for enc_form in ENCODED_FORMS.get(ch, []):
                if enc_form in after_prefix[:char_pos + 10]:
                    encoded = True
                    break

            if not encoded:
                reflected.append(ch)

        # Determine context from what precedes the probe in the response
        if reflected:
            context = self._determine_context(body, probe_idx)

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
        Test the endpoint once with the opposite HTTP method.
        GET -> POST (move URL params to body)
        POST -> GET (move body params to URL)

        Sends ONE extra request per endpoint.
        Reports if the swap returns a 200 (may indicate missing method checks).
        """
        issues  = []
        method  = req_info.getMethod().upper()
        request = brr.getRequest()
        params  = list(req_info.getParameters())

        query_params = [p for p in params if p.getType() == 0]
        body_params  = [p for p in params if p.getType() == 1]

        try:
            if method == "GET" and query_params:
                # Convert GET -> POST: move URL params into body
                new_body = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in query_params
                )
                # Build POST request: strip query string, add body
                path_only = url.getPath()
                headers   = [
                    "POST {} HTTP/1.1".format(path_only),
                    "Host: {}".format(url.getHost()),
                    "Content-Type: application/x-www-form-urlencoded",
                    "Content-Length: {}".format(len(new_body)),
                    "Connection: close",
                ]
                new_request = self._helpers.buildHttpMessage(
                    headers, self._helpers.stringToBytes(new_body))
                swap_label = "GET-to-POST"

            elif method == "POST" and body_params:
                # Convert POST -> GET: move body params to query string
                qs = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in body_params
                )
                path_qs = "{}?{}".format(url.getPath(), qs)
                headers = [
                    "GET {} HTTP/1.1".format(path_qs),
                    "Host: {}".format(url.getHost()),
                    "Connection: close",
                ]
                new_request = self._helpers.buildHttpMessage(headers, None)
                swap_label  = "POST-to-GET"
            else:
                return issues

            swap_response = self._callbacks.makeHttpRequest(
                http_service, new_request)
            if swap_response is None:
                return issues

            swap_resp_bytes = swap_response.getResponse()
            if swap_resp_bytes is None:
                return issues

            swap_resp_info  = self._helpers.analyzeResponse(swap_resp_bytes)
            status_code     = swap_resp_info.getStatusCode()

            # Flag if the swapped method returned 200 OK
            if status_code == 200:
                detail = (
                    "Method swap <b>{}</b> on <b>{}</b> returned HTTP 200.<br><br>"
                    "The endpoint accepts both methods. This may indicate:<br>"
                    "- Missing method-specific input validation<br>"
                    "- WAF rules that only cover one method<br>"
                    "- CSRF protections tied to POST only<br><br>"
                    "Recommendation: Manually test the swapped method with "
                    "XSS probe characters in all parameters."
                ).format(swap_label, url)
                issues.append(XSSIssue(
                    swap_response, url,
                    "[XSS Probe] Method Swap Accepted ({})".format(swap_label),
                    detail, "Information", "Certain"
                ))
                self._log("[MethodSwap] {} -> {} | {} | status=200".format(
                    method, swap_label, url))
            else:
                self._log("[MethodSwap] {} -> {} | {} | status={}".format(
                    method, swap_label, url, status_code))

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
