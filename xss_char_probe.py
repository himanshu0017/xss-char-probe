# -*- coding: utf-8 -*-
"""
XSS Char Probe - Burp Suite Extension (kxss-style logic)
=========================================================
Author  : For authorized pentesting only
Logic   : Based on tomnomnom/hacks/kxss

Three-stage detection:
  1. Reflection check  -- does the param's original value reflect in the body?
  2. Append check      -- append a random string; does that reflect too?
                          (filters out coincidental substring matches)
  3. Char check        -- for each special char, append "aprefix<CHAR>asuffix"
                          and check if "aprefix<CHAR>asuffix" appears RAW
                          in the response. Only flag chars that come back
                          unfiltered/unencoded between the unique markers.

The aprefix/asuffix anchors guarantee we find the exact injection point and
check only that char's reflection -- no encoding heuristics, no context
guessing, no false positives from unrelated page content.

Filters:
  - Strict text/html only (raw Content-Type header)
  - Skip 3xx redirects
  - Skip noisy tracking/analytics domains and params
  - Deduplicate per (host, path, param)

Method swap:
  - GET <-> POST converted with cookies preserved
  - Same three-stage logic applied to swapped requests

Installation:
  Extender -> Extensions -> Add -> Python -> select this file
"""

from burp import (IBurpExtender, IScannerCheck, IScanIssue, ITab,
                  IContextMenuFactory)
from javax.swing import (JPanel, JScrollPane, JTextArea, JLabel, JButton,
                         JMenuItem, JTextPane)
from javax.swing.text import SimpleAttributeSet, StyleConstants
from java.awt import BorderLayout, Font, Color, Dimension
from java.awt import Color as JColor
import re
import urllib
import random
import string

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
EXTENSION_NAME = "XSS Char Probe"
VERSION        = "3.0"

# Anchors used to locate the injection point exactly in the response
APPEND_PREFIX  = "aprefix"
APPEND_SUFFIX  = "asuffix"

# Special chars to test individually (kxss list)
TEST_CHARS = ['"', "'", '<', '>', '$', '|', '(', ')', '`', ':', ';', '{', '}']

# Subset that's actually XSS-relevant for severity
XSS_CRITICAL_CHARS = set(['<', '>', '"', "'"])

# ---------------------------------------------------------------------------
# Noise filters
# ---------------------------------------------------------------------------
SKIP_PARAMS = set([
    '__viewstate', '__eventvalidation', '__eventtarget', '__eventargument',
    '__viewstategenerator', '__scrollpositionx', '__scrollpositiony',
    '__previouspage', '__viewstateencrypted',
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
    'utm_id', 'utm_referrer',
    'gclid', 'gbraid', 'wbraid', 'gad_source', 'gad_campaignid',
    'gclgs', 'gclst', 'gcllp', 'gclaw', 'gclaw_src', 'gac',
    'cq_cmp', 'cq_med', 'cq_net', 'cq_plac', 'cq_plt',
    'gtm', 'gtag', 'tid', 'dl', 'dp', 'dt', 'dr',
    'gdpr', 'gdpr_consent', 'us_privacy', 'gpp', 'gpp_s', 'gpp_as',
    'tcfe', 'npa', 'dma',
    'cv', 'fst', 'bg', 'guid', 'async', 'capi', 'frm', 'fmt',
    'tiba', 'hn', 'label', 'value', 'auid', 'uaa', 'uab', 'uafvl',
    'uamb', 'uam', 'uap', 'uapv', 'uaw', 'ec_mode', 'random', 'rnd',
    'ipr', 'pscrd', 'fsk', 'crd', 'cerd', 'eitems', 'cid', 'is_vtc',
    'ezwbk', 'pscdl', 'gcs', 'gcd', 'tag_exp',
    'ref', 'ver', 'cb', 'ts', 'timestamp', 'nonce',
    'biw', 'bih', 'ei', 'opi', 'atyp',
    'sa', 'ved', 'nis', 'pf', 'co', 'ase', 'sig', 'cce', 'category',
])

SKIP_DOMAINS = [
    'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
    'doubleclick.net', 'googlesyndication.com',
    'google.co.', 'google.com/pagead', 'google.com/aclk',
    'google.com/client_204', 'google.com/url',
    'googleapis.com', 'gstatic.com',
    'facebook.com/tr', 'facebook.net',
    'twitter.com/i/', 'analytics.', 'liadm.com',
    'bing.com/action', 'bat.bing.com',
    'cdn.', 'fonts.', 'gravatar.com', 'wp.com/i/',
    'cloudflare.com', 'akamai',
]


# ---------------------------------------------------------------------------
# Extension entry point
# ---------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        self._seen_params  = set()
        self._seen_methods = set()

        callbacks.setExtensionName(EXTENSION_NAME)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        self._tab = XSSTab(self)
        callbacks.addSuiteTab(self._tab)

        self._log("[ {} v{} loaded ]".format(EXTENSION_NAME, VERSION))
        self._log("Logic: kxss-style 3-stage check (reflection + append + char)")
        self._log("Right-click any request -> 'Re-scan with XSS Char Probe' to force re-scan")
        self._log("-" * 60)

    # -----------------------------------------------------------------------
    # Context menu
    # -----------------------------------------------------------------------
    def createMenuItems(self, invocation):
        menu_items = []
        selected = invocation.getSelectedMessages()
        if selected and len(selected) > 0:
            item = JMenuItem("Re-scan with XSS Char Probe")
            item.addActionListener(
                lambda e, msgs=selected: self._force_rescan(msgs))
            menu_items.append(item)
        return menu_items

    def _force_rescan(self, messages):
        for msg in messages:
            try:
                req_info = self._helpers.analyzeRequest(msg)
                url      = req_info.getUrl()
                host     = url.getHost()
                path     = url.getPath()
                params   = [p for p in req_info.getParameters()
                            if p.getType() in (0, 1)]
                for p in params:
                    self._seen_params.discard((host, path, p.getName()))
                self._seen_methods.discard((host, path))
                self._log("[Rescan] {} -- starting".format(url))
                issues = self.doPassiveScan(msg)
                self._log("[Rescan] Done -- {} issues".format(len(issues)))
            except Exception as e:
                self._log("[ERROR] Rescan: {}".format(str(e)))

    # -----------------------------------------------------------------------
    # IScannerCheck
    # -----------------------------------------------------------------------
    def doActiveScan(self, brr, insertion_point):
        return []

    def consolidateDuplicateIssues(self, existing, new):
        if (existing.getIssueName() == new.getIssueName()
                and str(existing.getUrl()) == str(new.getUrl())):
            return -1
        return 0

    def doPassiveScan(self, brr):
        issues = []
        try:
            request  = brr.getRequest()
            response = brr.getResponse()
            if request is None or response is None:
                return issues

            req_info  = self._helpers.analyzeRequest(brr)
            resp_info = self._helpers.analyzeResponse(response)

            url    = req_info.getUrl()
            host   = url.getHost()
            path   = url.getPath()
            method = req_info.getMethod().upper()
            http_service = brr.getHttpService()

            # Skip noisy domains
            if self._is_noisy_target(host, path):
                return issues

            # Skip non-HTML responses
            if not self._is_html_response(response):
                return issues

            # Skip 3xx redirects
            status = resp_info.getStatusCode()
            if 300 <= status < 400:
                return issues

            params = [p for p in req_info.getParameters()
                      if p.getType() in (0, 1)
                      and not self._should_skip_param(p.getName())]
            if not params:
                return issues

            # Per-param 3-stage check
            for param in params:
                pname = param.getName()
                dedup = (host, path, pname)
                if dedup in self._seen_params:
                    continue
                self._seen_params.add(dedup)

                result = self._three_stage_check(
                    request, req_info, param, http_service, url)
                if result:
                    severity, chars, evidence = result
                    detail = self._build_detail(
                        url, pname, method, chars, evidence)
                    issues.append(XSSIssue(
                        brr, url,
                        "[XSS Probe] Reflected Special Chars",
                        detail, severity, "Firm"
                    ))
                    self._log("[{}] {} | param={} | unfiltered: {}".format(
                        severity, url, pname, ', '.join(chars)))

            # Method swap (once per endpoint)
            mkey = (host, path)
            if mkey not in self._seen_methods:
                self._seen_methods.add(mkey)
                swap_issues = self._method_swap(
                    brr, req_info, http_service, url, method)
                issues.extend(swap_issues)

        except UnicodeDecodeError:
            pass
        except UnicodeEncodeError:
            pass
        except Exception as e:
            err = str(e)
            if 'ascii' in err and 'codec' in err:
                pass
            else:
                self._log("[ERROR] doPassiveScan: {}".format(err))
        return issues

    # -----------------------------------------------------------------------
    # Three-stage check (kxss logic)
    # -----------------------------------------------------------------------
    def _three_stage_check(self, request, req_info, param, http_service, url):
        """
        Returns (severity, list_of_unfiltered_chars, evidence_snippet)
        or None if the param doesn't reflect at all / is filtered.
        """
        pname = param.getName()
        pval  = param.getValue()

        # ---- Stage 1: does the original value reflect? ----
        # Use the existing response if we have it from Burp (no extra request)
        # or send a fresh GET with the original value.
        body1 = self._send_with_value(request, param, pval, http_service)
        if body1 is None or pval == '' or pval not in body1:
            return None

        # ---- Stage 2: append a random string -- does that reflect too? ----
        # This filters out coincidental matches where pval happens to be a
        # common substring on the page (e.g. pval="false" on a page with
        # "false" in unrelated places).
        nonce = self._random_nonce(12)
        body2 = self._send_with_value(
            request, param, pval + nonce, http_service)
        if body2 is None or nonce not in body2:
            return None

        # ---- Stage 3: char-by-char with anchors ----
        unfiltered = []
        evidence_snippets = []
        for ch in TEST_CHARS:
            payload = APPEND_PREFIX + ch + APPEND_SUFFIX
            body3 = self._send_with_value(
                request, param, pval + payload, http_service)
            if body3 is None:
                continue
            # Look for the EXACT marker -- aprefixCHARasuffix between anchors
            if payload in body3:
                unfiltered.append(ch)
                # Capture context around first occurrence for the report
                idx = body3.find(payload)
                snippet = body3[max(0, idx - 40):idx + len(payload) + 40]
                snippet = snippet.replace('\n', ' ').replace('\r', ' ')
                evidence_snippets.append("'{}' -> {}".format(
                    ch, snippet[:200]))

        if not unfiltered:
            return None

        # Severity based on which chars came through unfiltered
        critical = [c for c in unfiltered if c in XSS_CRITICAL_CHARS]
        if '<' in critical or '>' in critical:
            severity = "High"
        elif '"' in critical or "'" in critical:
            severity = "Medium"
        else:
            severity = "Low"

        evidence = '\n'.join(evidence_snippets[:5])
        return (severity, unfiltered, evidence)

    def _send_with_value(self, request, param, new_value, http_service):
        """
        Send a request with the given parameter set to new_value.
        Returns the response body string, or None on failure.
        """
        try:
            new_request = self._helpers.updateParameter(
                request,
                self._helpers.buildParameter(
                    param.getName(),
                    urllib.quote(new_value, safe=''),
                    param.getType()
                )
            )
            resp = self._callbacks.makeHttpRequest(http_service, new_request)
            if resp is None:
                return None
            resp_bytes = resp.getResponse()
            if resp_bytes is None:
                return None
            resp_info = self._helpers.analyzeResponse(resp_bytes)
            return self._safe_decode_body(resp_bytes, resp_info)
        except Exception:
            return None

    def _random_nonce(self, length):
        """Generate a random alphanumeric string of the given length."""
        chars = string.ascii_lowercase + string.digits
        return ''.join(random.choice(chars) for _ in range(length))

    # -----------------------------------------------------------------------
    # Method swap
    # -----------------------------------------------------------------------
    def _method_swap(self, brr, req_info, http_service, url, method):
        issues = []
        params = list(req_info.getParameters())
        query_params = [p for p in params if p.getType() == 0]
        body_params  = [p for p in params if p.getType() == 1]

        try:
            request     = brr.getRequest()
            body_offset = req_info.getBodyOffset()
            has_body    = len(request[body_offset:]) > 0

            orig_headers = self._get_original_headers(req_info)

            if method == "GET" and query_params:
                swap_label = "GET-to-POST"
                swap_params = [p for p in query_params
                               if not self._should_skip_param(p.getName())]
                if not swap_params:
                    return issues
                base_body = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in query_params)
                base_headers = (
                    ["POST {} HTTP/1.1".format(url.getPath())]
                    + orig_headers
                    + ["Content-Type: application/x-www-form-urlencoded",
                       "Content-Length: {}".format(len(base_body))])
                swapped_request = self._helpers.buildHttpMessage(
                    base_headers, self._helpers.stringToBytes(base_body))

            elif method == "POST" and body_params:
                swap_label = "POST-to-GET"
                swap_params = [p for p in body_params
                               if not self._should_skip_param(p.getName())]
                if not swap_params:
                    return issues
                qs = '&'.join(
                    "{}={}".format(
                        urllib.quote(p.getName(), safe=''),
                        urllib.quote(p.getValue(), safe=''))
                    for p in body_params)
                base_headers = (
                    ["GET {}?{} HTTP/1.1".format(url.getPath(), qs)]
                    + orig_headers)
                swapped_request = self._helpers.buildHttpMessage(
                    base_headers, None)
            else:
                return issues

            swap_resp = self._callbacks.makeHttpRequest(
                http_service, swapped_request)
            if swap_resp is None:
                return issues
            swap_bytes = swap_resp.getResponse()
            if swap_bytes is None:
                return issues
            swap_info = self._helpers.analyzeResponse(swap_bytes)
            sc = swap_info.getStatusCode()
            self._log("[MethodSwap] {} | {} | status={}".format(
                swap_label, url, sc))

            if sc != 200 or not self._is_html_response(swap_bytes):
                return issues

            # Run the 3-stage check on each param via the swapped method
            swap_req_info = self._helpers.analyzeRequest(
                http_service, swapped_request)

            for param in swap_req_info.getParameters():
                if param.getType() not in (0, 1):
                    continue
                if self._should_skip_param(param.getName()):
                    continue
                key = (url.getHost(), url.getPath(),
                       param.getName() + "_" + swap_label)
                if key in self._seen_params:
                    continue
                self._seen_params.add(key)

                result = self._three_stage_check(
                    swapped_request, swap_req_info, param,
                    http_service, url)
                if result:
                    severity, chars, evidence = result
                    detail = self._build_detail(
                        url, param.getName(),
                        "POST (swapped)" if swap_label == "GET-to-POST" else "GET (swapped)",
                        chars, evidence)
                    issues.append(XSSIssue(
                        swap_resp, url,
                        "[XSS Probe] Reflected Special Chars via {}".format(swap_label),
                        detail, severity, "Firm"
                    ))
                    self._log("[{}][{}] {} | param={} | unfiltered: {}".format(
                        severity, swap_label, url, param.getName(),
                        ', '.join(chars)))

        except Exception as e:
            self._log("[WARN] Method swap failed: {}".format(str(e)))
        return issues

    def _get_original_headers(self, req_info):
        skip = ('content-type:', 'content-length:',
                'transfer-encoding:', 'connection:')
        result = []
        for i, h in enumerate(req_info.getHeaders()):
            if i == 0:
                continue
            if h.lower().startswith(skip):
                continue
            result.append(h)
        result.append("Connection: close")
        return result

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _is_html_response(self, response):
        try:
            for h in self._helpers.analyzeResponse(response).getHeaders():
                if h.lower().startswith('content-type:'):
                    return 'text/html' in h.lower()
        except Exception:
            pass
        return False

    def _is_noisy_target(self, host, path):
        target = (host + path).lower()
        return any(p in target for p in SKIP_DOMAINS)

    def _should_skip_param(self, name):
        return name.lower() in SKIP_PARAMS

    def _safe_decode_body(self, response_bytes, response_info):
        """Decode response body, handling gzip/deflate and binary safely."""
        try:
            body_bytes = response_bytes[response_info.getBodyOffset():]
            if not body_bytes:
                return ''

            encoding = ''
            for h in response_info.getHeaders():
                if h.lower().startswith('content-encoding:'):
                    encoding = h.split(':', 1)[1].strip().lower()
                    break

            if 'gzip' in encoding or 'deflate' in encoding:
                try:
                    from java.io import ByteArrayInputStream
                    from java.util.zip import GZIPInputStream, InflaterInputStream
                    import jarray
                    java_bytes = jarray.array(body_bytes, 'b')
                    bais = ByteArrayInputStream(java_bytes)
                    if 'gzip' in encoding:
                        stream = GZIPInputStream(bais)
                    else:
                        stream = InflaterInputStream(bais)
                    out = []
                    buf = jarray.zeros(4096, 'b')
                    while True:
                        n = stream.read(buf)
                        if n <= 0:
                            break
                        out.extend(buf[:n])
                    stream.close()
                    body_bytes = out
                except Exception:
                    return None

            try:
                return self._helpers.bytesToString(body_bytes)
            except Exception:
                return ''.join(
                    chr(b & 0xff) if (b & 0xff) < 128 else '?'
                    for b in body_bytes)
        except Exception:
            return None

    def _build_detail(self, url, pname, method, chars, evidence):
        char_list = ', '.join("<b>{}</b>".format(self._html_esc(c))
                              for c in chars)
        return (
            "Parameter <b>{}</b> on <b>{}</b> ({}) reflects the following "
            "special characters UNFILTERED in the response:<br><br>"
            "{}<br><br>"
            "Detection method: kxss-style three-stage check<br>"
            " 1. Confirmed parameter reflects in response<br>"
            " 2. Confirmed appended random string also reflects "
            "(rules out coincidental match)<br>"
            " 3. For each char, appended <code>{}CHAR{}</code> and verified "
            "the EXACT marker appears in the response<br><br>"
            "Evidence (first 5 chars):<br>"
            "<pre>{}</pre><br>"
            "Manual verification with a context-aware payload required to "
            "confirm exploitability."
        ).format(
            self._html_esc(pname), url, method, char_list,
            APPEND_PREFIX, APPEND_SUFFIX,
            self._html_esc(evidence))

    def _html_esc(self, s):
        return (s.replace('&', '&amp;').replace('<', '&lt;')
                 .replace('>', '&gt;').replace('"', '&quot;'))

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
            "  {} v{}  --  kxss-style 3-stage detection".format(
                EXTENSION_NAME, VERSION))
        header.setFont(Font("Monospaced", Font.BOLD, 13))
        header.setForeground(Color(220, 80, 80))

        self._text_pane = JTextPane()
        self._text_pane.setEditable(False)
        self._text_pane.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._text_pane.setBackground(Color(18, 18, 18))

        # Pre-build colored styles
        self._styles = {}
        color_map = {
            'high':   JColor(255,  80,  80),
            'medium': JColor(255, 180,  50),
            'low':    JColor(255, 230, 100),
            'swap':   JColor(100, 180, 255),
            'info':   JColor(160, 255, 160),
            'error':  JColor(255,  60,  60),
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
        ml = msg.lower()
        if '[high]' in ml:        style_key = 'high'
        elif '[medium]' in ml:    style_key = 'medium'
        elif '[low]' in ml:       style_key = 'low'
        elif '[error]' in ml:     style_key = 'error'
        elif any(x in ml for x in ['[methodswap]', '[get-to-post]',
                                    '[post-to-get]', '[rescan]']):
            style_key = 'swap'
        else:                     style_key = 'info'

        doc = self._text_pane.getStyledDocument()
        try:
            doc.insertString(doc.getLength(), msg + "\n", self._styles[style_key])
        except Exception:
            pass
        self._text_pane.setCaretPosition(doc.getLength())

    def _clear(self):
        self._text_pane.setText("")
        self._extender._seen_params.clear()
        self._extender._seen_methods.clear()
        self.append("[ Log cleared -- dedup cache reset ]")


# ---------------------------------------------------------------------------
# IScanIssue
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
        return ("Special characters such as < > \" ' reflected unfiltered "
                "may indicate Cross-Site Scripting (XSS) vulnerabilities.")

    def getRemediationBackground(self):
        return ("Apply context-aware output encoding (HTML, attribute, JS). "
                "Use Content-Security-Policy headers. "
                "Validate and sanitise all user input server-side.")
