---
name: bug-bounty-methodology
description: Bug bounty hunting methodology with 5-phase non-linear workflow and developer psychology analysis
license: MIT
metadata:
  category: web-security
  locale: en
  phase: v1
---

## What this skill does

Provides a complete cognitive and operational framework for bug bounty hunting sessions. Combines a 5-phase non-linear workflow (Recon → Map → Discover → Prove → Report) with four thinking domains (Critical, Multi-Perspective, Tactical, Strategic) and developer psychology reversal techniques. Routes decisions about what to test, which tool to use, and how to escalate findings based on phase, target type, and time elapsed.

## When to use

- At the start of any new bug bounty hunting session
- When switching to a new program or target
- When feeling stuck or unsure what to do next
- When a finding has low impact and you want to escalate it
- When asking "what should I test next?" or "where am I in the process?"
- When a WAF or filter is blocking your payload and you need a bypass strategy

## Prerequisites

- A valid, authorized bug bounty scope (HackerOne, Bugcrowd, Intigriti, Immunefi, or private program)
- A proxy tool (Burp Suite or Caido) running and intercepting traffic
- Two test accounts on the target application (attacker account A, victim account B)
- No external tools are required — this skill is a cognitive framework

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `BB_TARGET` | Yes | Target domain or program name |
| `BB_SCOPE` | Yes | In-scope assets (domains, features, APIs) |
| `BB_SESSION_GOAL` | Yes | One of: Confidentiality, Integrity, Availability, ATO, RCE |
| `BB_VULN_CLASS` | Yes | 1-2 vuln classes to focus on this session (e.g., IDOR, SSRF) |
| `BB_ROUTE` | Optional | `wide` (breadth-first) or `deep` (depth-first, default: wide for new targets) |
| `BB_TIME_LIMIT` | Optional | Session time budget in minutes (default: 120) |

## Workflow

### Step 1: Session start — define, select, execute

Before touching any tool, answer these three questions:

```bash
# Print your session contract — fill this in before starting
cat <<EOF
SESSION CONTRACT
===============
Target  : ${BB_TARGET}
Goal    : ${BB_SESSION_GOAL}   # One of: Confidentiality / Integrity / ATO / RCE / Availability
Focus   : ${BB_VULN_CLASS}     # 1-2 classes only (e.g., IDOR, SSRF)
Route   : ${BB_ROUTE:-wide}    # wide = many endpoints, deep = one feature thoroughly
Budget  : ${BB_TIME_LIMIT:-120} minutes
EOF

# Route selection guide
# Signal                          -> Route
# New program, first day          -> wide
# Wildcard scope *.target.com     -> wide
# Scope update (new domain added) -> wide
# Main webapp, been here >3 days  -> deep
# Found one interesting subdomain -> deep
```

### Step 2: Recon — maximize attack surface

```bash
# Wide approach: subdomain enum -> DNS resolve -> HTTP probe -> tech detection
export TARGET="${BB_TARGET}"

# Passive subdomain enumeration (no detection)
subfinder -d "$TARGET" -silent -o /tmp/subs_passive.txt
cat /tmp/subs_passive.txt | wc -l && echo "subdomains found"

# Resolve and probe live hosts
cat /tmp/subs_passive.txt | httpx -silent -status-code -title -tech-detect \
  -o /tmp/live_hosts.txt
cat /tmp/live_hosts.txt | grep -E "200|301|302" | head -30

# URL harvesting: archives (forgotten endpoints) -> active crawl
echo "$TARGET" | gau --threads 5 --subs 2>/dev/null | tee /tmp/urls_archived.txt | wc -l
katana -u "https://$TARGET" -silent -js-crawl -depth 3 -o /tmp/urls_crawled.txt

# JS file extraction for hidden routes and secrets
cat /tmp/urls_archived.txt /tmp/urls_crawled.txt | grep "\.js$" | sort -u > /tmp/js_files.txt
cat /tmp/js_files.txt | while read url; do
  curl -sk "$url" | jsluice urls 2>/dev/null
done | sort -u | tee /tmp/endpoints_from_js.txt | wc -l
echo "endpoints extracted from JS"

# Developer psychology — check old API versions
curl -sk "https://$TARGET/api/v1/" -o /dev/null -w "v1: %{http_code}\n"
curl -sk "https://$TARGET/api/v2/" -o /dev/null -w "v2: %{http_code}\n"
curl -sk "https://$TARGET/api/v3/" -o /dev/null -w "v3: %{http_code}\n"
```

### Step 3: Map and analyze — understand the application

```bash
# Download JS files for static analysis
mkdir -p /tmp/js_analysis
cat /tmp/js_files.txt | head -20 | while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -sk "$url" -o "/tmp/js_analysis/$filename"
done

# Find hidden parameters in JS
grep -rh "params\|query\|body\|payload\|data\[" /tmp/js_analysis/ 2>/dev/null \
  | grep -oE '"[a-zA-Z_][a-zA-Z0-9_]{2,30}"' | sort | uniq -c | sort -rn | head -30

# Discover hidden parameters on live endpoints
# (run arjun against interesting endpoints found in Step 2)
arjun -u "https://$TARGET/api/users" --stable 2>/dev/null | grep "Found"

# Check for debug/admin panels (developer psychology: devs forget to remove these)
for path in /admin /administrator /debug /test /staging /dev /api-docs \
            /swagger-ui.html /graphql /.env /config.json /server-status; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[$code] https://$TARGET$path"
done

# Identify auth model
curl -sk "https://$TARGET/api/me" -H "Authorization: Bearer INVALID" \
  -v 2>&1 | grep -E "HTTP/|www-authenticate|set-cookie|x-auth" | head -10
```

### Step 4: Vulnerability discovery — apply developer psychology

```bash
# Developer psychology reversal — what did developers likely forget?
# 1. Sibling endpoints: if /api/admin/users has auth, /api/admin/export probably doesn't
# 2. New features ship fast -> auth checks added to old flow but not new
# 3. Complex flows (coupon + points + refund) have edge case bugs

# Decision flow: what are you testing?
# ID parameter (user_id, order_id) -> test IDOR (use web-vuln-idor skill)
# URL/webhook input                -> test SSRF (use web-vuln-ssrf skill)
# Price/quantity/coupon            -> test business logic (use web-vuln-business-logic skill)
# Text reflected in page           -> test XSS
# Login/2FA/password reset         -> test auth bypass
# Template/wiki editor             -> test SSTI

# What-If experiments to run
TARGET_URL="https://${BB_TARGET}"

# Test 1: Skip a workflow step
# Normal: GET /checkout -> POST /checkout -> GET /checkout/confirm
# Attack: jump directly to /checkout/confirm
curl -sk -b "session=YOUR_SESSION" "$TARGET_URL/checkout/confirm" \
  -w "\nHTTP: %{http_code}\n" | tail -5

# Test 2: Mass assignment — add unexpected fields to profile update
curl -sk -X PUT "$TARGET_URL/api/user/profile" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name":"test","role":"admin","is_admin":true,"plan":"enterprise"}' \
  -w "\nHTTP: %{http_code}\n"

# Test 3: HTTP method swap — PUT protected but DELETE not?
curl -sk -X DELETE "$TARGET_URL/api/resource/VICTIM_ID" \
  -H "Authorization: Bearer ATTACKER_TOKEN" \
  -w "\nHTTP: %{http_code}\n"

# Error-based probing to find injection points
for payload in "'" '"' '{{7*7}}' '${7*7}' '; sleep 5; #'; do
  code=$(curl -sk -o /tmp/err_probe.out -w "%{http_code}" \
    "$TARGET_URL/api/search?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")")
  size=$(wc -c < /tmp/err_probe.out)
  echo "[$code|${size}B] payload: $payload"
done
```

### Step 5: Prove and escalate — maximize impact

```bash
# Escalation decision by finding type:
# XSS found          -> steal cookie/token -> session hijack -> ATO
# IDOR found         -> read PII or write data -> chain to ATO
# SSRF found         -> reach cloud metadata -> extract IAM keys -> RCE
# SQLi found         -> extract password hashes -> INTO OUTFILE for webshell

# Minimize attack prerequisites (for severity):
# 0 clicks = Critical
# 1 email click = High
# Requires phishing = Medium

# Prove scale of IDOR (turn Medium into High):
for id in $(seq 1 20); do
  result=$(curl -sk -H "Authorization: Bearer ATTACKER_TOKEN" \
    "https://${BB_TARGET}/api/users/$id" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('email','') + ' | ' + d.get('name',''))
except: print('parse error')
")
  echo "ID $id: $result"
done

# A->B signal: same developer made multiple mistakes — hunt 20 min for siblings
# After finding a bug in /api/v1/orders, check:
for endpoint in /api/v1/invoices /api/v1/reports /api/v1/exports \
                /api/v1/admin /api/v1/payments; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer ATTACKER_TOKEN" \
    "https://${BB_TARGET}${endpoint}/VICTIM_ID")
  echo "[$code] $endpoint"
done
```

### Step 6: Time management — rotation rules

```bash
# Session timer — print rotation reminders
SESSION_START=$(date +%s)
check_time() {
  local now=$(date +%s)
  local elapsed=$(( (now - SESSION_START) / 60 ))
  echo "Elapsed: ${elapsed} min"
  [ $elapsed -ge 20 ] && echo "20-MIN RULE: Rotate endpoint if no progress"
  [ $elapsed -ge 45 ] && echo "45-MIN RULE: STOP. Rabbit hole detected. Move on."
}
# Call check_time after each testing block

# Anti-patterns to avoid:
# - Program hopping: stick with one target minimum 30 hours
# - Tool-only hunting: automation finds duplicates, manual finds unique bugs
# - No goal: always define BB_SESSION_GOAL before starting
# - Ignoring "weird" behaviors: log anomalies even if not immediately exploitable
echo "Session started at $(date). Goal: ${BB_SESSION_GOAL}. Focus: ${BB_VULN_CLASS}."
```

## Done when

- Session goal (Confidentiality / Integrity / ATO / RCE / Availability) is achieved with a reproducible proof of concept
- Finding is validated: realistic attack conditions, confirmed impact, no false positive
- HTTP request/response pair is captured in Burp or Caido for the report
- Business impact is quantified (e.g., "attacker can read PII of all N users")
- CVSS 3.1 score is calculated and matches the actual demonstrated impact
- Report is written and submitted to the program platform

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| No subdomains found | Target has no public subdomains or passive sources exhausted | Try Google Dorks, GitHub search, Shodan, certificate transparency logs |
| Every endpoint returns 403 | Auth model not understood | Re-map auth (tokens, cookies, API keys), check JS for auth flow |
| WAF blocks all payloads | WAF is tuned for common payloads | Use `wafw00f` to identify WAF, then apply vendor-specific bypass techniques |
| All IDs are UUIDs | No predictable IDs to enumerate | Find UUID leak source (email invite, shared links, API responses to other endpoints) |
| Stuck for 45+ minutes | Rabbit hole — single parameter consuming all time | Hard stop. Rotate to next endpoint. Add to "investigate later" list. |
| No findings after 10 hours | Testing known patterns only | Switch from vuln-based to feature-based route: find most complex business flow and audit it |
| Low-impact findings only | Can't escalate alone | Find connector gadget: another low-impact bug that chains with the first |

## Notes

- Only use against programs where you have explicit authorization. Never test without scope confirmation.
- Wide vs Deep route is not a permanent choice — reassess every session based on what you found last session.
- The 20-minute rotation rule prevents rabbit holes: if an endpoint shows no progress in 20 minutes, move to the next.
- Developer psychology is the highest-leverage mindset: ask "what shortcut would a developer take here?" before every test.
- Record all "weird but not exploitable" behaviors in session notes — they are future chaining gadgets.
- Tool routing by phase: passive recon first (no detection), then active (naabu/katana), then targeted exploitation.
- After finding one bug, apply the A→B signal: the same developer made more mistakes nearby. Hunt siblings for 20 minutes.
