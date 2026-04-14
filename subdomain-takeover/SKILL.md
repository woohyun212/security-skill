---
name: subdomain-takeover
description: Subdomain takeover detection and verification for dangling DNS records
license: MIT
metadata:
  category: recon
  locale: en
  phase: v1
---

## What this skill does

Detects and verifies subdomain takeover vulnerabilities by identifying dangling DNS CNAME records that point to unclaimed or deprovisioned third-party services. For each CNAME, resolves the target, checks the HTTP response against known vulnerable-service fingerprints, and confirms exploitability by verifying the resource can be claimed. Covers 18+ vulnerable services including GitHub Pages, AWS S3, Heroku, Netlify, Azure (Traffic Manager, Blob, CloudApp), Shopify, Fastly, Ghost, Pantheon, Tumblr, WordPress.com, Cargo Collective, Surge.sh, Bitbucket, Zendesk, Readme.io, and Statuspage.

## When to use

- During recon on a bug bounty program to find high-impact, low-effort findings
- After subdomain enumeration (e.g. from the `subdomain-enum` skill) to check each live CNAME
- When auditing an organization's DNS records for hygiene and dangling entries
- After a product decommissioning or cloud migration to verify DNS cleanup was complete

## Prerequisites

- `dig` installed (part of `dnsutils` on Debian/Ubuntu, `bind-utils` on RHEL/CentOS):
  ```bash
  apt install dnsutils   # Debian/Ubuntu
  ```
- `curl` installed
- `httpx` installed (for bulk HTTP probing):
  ```bash
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
- One of the following automated scanners (choose one):
  - **subjack**:
    ```bash
    go install github.com/haccer/subjack@latest
    ```
  - **nuclei** with takeover templates:
    ```bash
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates
    ```
- Environment variable `SECSKILL_TARGET_DOMAIN`: target root domain
- Environment variable `SECSKILL_SUBDOMAIN_LIST`: path to a file of subdomains (one per line); can be output from the `subdomain-enum` skill

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_SUBDOMAIN_LIST` | required | Path to file containing subdomains to check (one per line) |
| `SECSKILL_TARGET_DOMAIN` | required | Root domain (used for labeling output files) |
| `SECSKILL_OUTPUT_DIR` | optional | Directory to save results (default: `./output`) |
| `SECSKILL_USE_SUBJACK` | optional | Set to `true` to run subjack (default: `false`) |
| `SECSKILL_USE_NUCLEI` | optional | Set to `true` to run nuclei takeover templates (default: `false`) |

## Workflow

### Step 1: Prepare environment

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?Set SECSKILL_TARGET_DOMAIN}"
export SUBLIST="${SECSKILL_SUBDOMAIN_LIST:?Set SECSKILL_SUBDOMAIN_LIST}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

echo "[*] Target domain : $TARGET"
echo "[*] Subdomain list: $SUBLIST ($(wc -l < "$SUBLIST") entries)"
echo "[*] Output dir    : $OUTDIR"
```

### Step 2: Resolve CNAME records for all subdomains

For each subdomain, resolve the CNAME chain to find the ultimate target. A dangling record exists when the CNAME target belongs to a third-party service that no longer has the resource provisioned.

```bash
echo "[*] Resolving CNAME records..."
> "$OUTDIR/cnames_${TARGET}.txt"

while IFS= read -r SUB; do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null | sed 's/\.$//')
  if [ -n "$CNAME" ]; then
    echo "$SUB -> $CNAME" | tee -a "$OUTDIR/cnames_${TARGET}.txt"
  fi
done < "$SUBLIST"

TOTAL_CNAMES=$(wc -l < "$OUTDIR/cnames_${TARGET}.txt")
echo "[+] CNAMEs found: $TOTAL_CNAMES"
echo "[+] Saved to: $OUTDIR/cnames_${TARGET}.txt"
```

### Step 3: Check HTTP responses for known takeover fingerprints

Probe each CNAME-bearing subdomain over HTTP/HTTPS and look for service-specific error responses that indicate the resource is unclaimed.

```bash
echo "[*] Probing CNAME subdomains for takeover fingerprints..."

# Fingerprint database: service name -> response string indicating unclaimed resource
# See REFERENCE.md for the full fingerprint table.
declare -A FINGERPRINTS
FINGERPRINTS["github-pages"]="There isn't a GitHub Pages site here"
FINGERPRINTS["s3"]="NoSuchBucket"
FINGERPRINTS["heroku"]="No such app"
FINGERPRINTS["netlify"]="Not Found - Request ID"
FINGERPRINTS["azure-trafficmanager"]="404 Not Found"
FINGERPRINTS["azure-blob"]="BlobNotFound"
FINGERPRINTS["azure-cloudapp"]="404 Web Site not found"
FINGERPRINTS["shopify"]="Sorry, this shop is currently unavailable"
FINGERPRINTS["fastly"]="Fastly error: unknown domain"
FINGERPRINTS["ghost"]="Failed to resolve DNS for"
FINGERPRINTS["pantheon"]="The gods are wise, but do not know of the site which you seek"
FINGERPRINTS["tumblr"]="There's nothing here"
FINGERPRINTS["wordpress-com"]="Do you want to register"
FINGERPRINTS["cargo-collective"]="404 Not Found"
FINGERPRINTS["surge-sh"]="project not found"
FINGERPRINTS["bitbucket"]="Repository not found"
FINGERPRINTS["zendesk"]="Help Center Closed"
FINGERPRINTS["readme-io"]="Project doesnt exist"
FINGERPRINTS["statuspage"]="Better Uptime"

> "$OUTDIR/vulnerable_${TARGET}.txt"

while IFS= read -r SUB; do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null | sed 's/\.$//')
  [ -z "$CNAME" ] && continue

  RESPONSE=$(curl -sk --max-time 10 "https://$SUB" 2>/dev/null || curl -sk --max-time 10 "http://$SUB" 2>/dev/null)
  [ -z "$RESPONSE" ] && continue

  for SERVICE in "${!FINGERPRINTS[@]}"; do
    FP="${FINGERPRINTS[$SERVICE]}"
    if echo "$RESPONSE" | grep -qi "$FP"; then
      echo "[VULNERABLE] $SUB -> $CNAME | Service: $SERVICE | Fingerprint: $FP" \
        | tee -a "$OUTDIR/vulnerable_${TARGET}.txt"
      break
    fi
  done
done < "$SUBLIST"

VULN_COUNT=$(wc -l < "$OUTDIR/vulnerable_${TARGET}.txt")
echo "[+] Potentially vulnerable subdomains: $VULN_COUNT"
echo "[+] Results saved to: $OUTDIR/vulnerable_${TARGET}.txt"
```

### Step 4: Automated scan with subjack (optional)

subjack automates fingerprint detection across all subdomains and checks against an up-to-date fingerprints database.

```bash
if [ "${SECSKILL_USE_SUBJACK:-false}" = "true" ]; then
  echo "[*] Running subjack..."
  subjack \
    -w "$SUBLIST" \
    -t 100 \
    -timeout 30 \
    -ssl \
    -c "$(go env GOPATH)/pkg/mod/github.com/haccer/subjack@*/fingerprints.json" \
    -o "$OUTDIR/subjack_${TARGET}.txt" \
    -v
  echo "[+] subjack results saved to: $OUTDIR/subjack_${TARGET}.txt"
else
  echo "[*] Skipping subjack (enable with SECSKILL_USE_SUBJACK=true)"
fi
```

### Step 5: Automated scan with nuclei takeover templates (optional)

nuclei's takeover template pack covers 50+ services and is updated regularly by the ProjectDiscovery community.

```bash
if [ "${SECSKILL_USE_NUCLEI:-false}" = "true" ]; then
  echo "[*] Running nuclei takeover templates..."
  nuclei \
    -l "$SUBLIST" \
    -t http/takeovers/ \
    -o "$OUTDIR/nuclei_takeover_${TARGET}.txt" \
    -silent
  echo "[+] nuclei results saved to: $OUTDIR/nuclei_takeover_${TARGET}.txt"
else
  echo "[*] Skipping nuclei (enable with SECSKILL_USE_NUCLEI=true)"
fi
```

### Step 6: Manual verification of candidate subdomains

For each candidate identified in Steps 3–5, manually verify exploitability before reporting. False positives are common — confirm that the specific resource (bucket, GitHub Pages repo, Heroku app name, etc.) is truly unclaimed.

```bash
# Manual verification procedure for each candidate:
CANDIDATE_SUB="<subdomain from vulnerable list>"
CANDIDATE_CNAME=$(dig +short CNAME "$CANDIDATE_SUB" | sed 's/\.$//')
echo "[*] Verifying: $CANDIDATE_SUB -> $CANDIDATE_CNAME"

# 1. Confirm CNAME resolution
dig +short CNAME "$CANDIDATE_SUB"

# 2. Check HTTP response and status code
curl -svk "https://$CANDIDATE_SUB" 2>&1 | grep -E "< HTTP|There isn|NoSuch|No such|not found" | head -20

# 3. Identify the service from the CNAME target
echo "$CANDIDATE_CNAME" | grep -oE "(github\.io|s3\.amazonaws\.com|herokuapp\.com|netlify\.app|azurewebsites\.net|trafficmanager\.net|blob\.core\.windows\.net|shopify\.com|fastly\.net|ghost\.io|pantheonsite\.io|tumblr\.com|wordpress\.com|cargocollective\.com|surge\.sh|bitbucket\.io|zendesk\.com|readme\.io|statuspage\.io)"
```

Service-specific claim verification:

> **Reference**: See [REFERENCE.md](REFERENCE.md) for the service-specific claim verification table.

### Step 7: Attempt claim (authorized testing only)

Only attempt to claim a resource if you have explicit written authorization from the domain owner. Claiming a subdomain without authorization constitutes unauthorized access in most jurisdictions.

```bash
# Example: GitHub Pages claim (authorized only)
# 1. Create a GitHub repository matching the expected Pages URL
# 2. Add a simple index.html with a non-harmful proof-of-concept page
# 3. Enable GitHub Pages on the repository
# 4. Verify the subdomain resolves to your proof page

echo "AUTHORIZED TESTING ONLY — do not claim without written permission"
echo "[*] If claiming for PoC: create a benign proof page (e.g. 'Subdomain takeover PoC - <your name>') "
echo "[*] Do NOT host any malicious content on the claimed resource"
echo "[*] Report immediately and release the resource after confirmation"
```

### Step 8: Document affected subdomains and produce report

```bash
echo "[*] Generating summary report..."

cat > "$OUTDIR/takeover_report_${TARGET}.md" << EOF
## Subdomain Takeover Report: $TARGET

**Scan date**: $(date +%Y-%m-%d)
**Subdomains scanned**: $(wc -l < "$SUBLIST")
**CNAMEs found**: $TOTAL_CNAMES
**Vulnerable candidates**: $VULN_COUNT

### Confirmed Vulnerable Subdomains

| Subdomain | CNAME Target | Service | Severity | Status |
|-----------|-------------|---------|----------|--------|
$(cat "$OUTDIR/vulnerable_${TARGET}.txt" 2>/dev/null | sed 's/\[VULNERABLE\] //g' | awk -F' -> | Service: | Fingerprint: ' '{print "| "$1" | "$2" | "$3" | High | Unverified |"}')

### Remediation

For each affected subdomain:
1. Remove the dangling DNS CNAME record immediately, OR
2. Re-provision the target service resource if it is still needed
3. Implement DNS record review as part of decommissioning checklists

### CVSS

Subdomain takeover is typically rated **High (CVSS 8.1)**:
- Attack Vector: Network, Attack Complexity: Low, Privileges Required: None
- User Interaction: Required (victim must visit the subdomain)
- Scope: Changed, Confidentiality: High, Integrity: High, Availability: None

Impact increases to **Critical** if:
- The subdomain handles authentication cookies (cookie scope inheritance)
- The subdomain is trusted by CORS policies of the main application
- The subdomain can serve malicious JS loaded by the main application
EOF

echo "[+] Report saved to: $OUTDIR/takeover_report_${TARGET}.md"
```

## Done when

- All subdomains from the input list have been checked for CNAME records
- Each CNAME-bearing subdomain has been probed and compared against the fingerprint database
- Automated scanners (subjack or nuclei) have been run if enabled
- Each candidate has been manually verified for true exploitability (not just a matching fingerprint)
- The final report lists confirmed vulnerable subdomains with CNAME target, service, severity, and remediation advice

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `subjack: command not found` | Not installed or not in PATH | Run `go install github.com/haccer/subjack@latest`; ensure `$(go env GOPATH)/bin` is in `$PATH` |
| CNAME resolves but HTTP probe returns no response | Service is active but on a non-standard port | Probe ports 80, 443, 8080; some services use HTTP-only on port 80 |
| Fingerprint matched but resource is actually claimed | Stale fingerprint or partial page load | Manually browse the URL and attempt to reproduce the claim; check for custom 404 pages mimicking takeover messages |
| High false positive rate | Generic 404 pages matching fingerprints | Tune fingerprint strings to be more specific; cross-check with service-specific claim verification in Step 6 |
| nuclei templates not found | Templates not downloaded | Run `nuclei -update-templates` first |
| dig returns NXDOMAIN for subdomain | DNS record already removed | Mark as remediated; no longer vulnerable |

## Notes

- Subdomain takeover is typically rated High severity (CVSS ~8.1) standalone, but can escalate to Critical if the subdomain is in the cookie scope of the root domain, trusted by the main app's CORS policy, or included as a script source — enabling session hijacking or XSS against all users of the main application.
- GitHub Pages takeovers are the most common and easiest to verify — a 404 with "There isn't a GitHub Pages site here" is highly reliable.
- AWS S3 bucket takeovers require knowing the region; try `us-east-1` first, then enumerate other regions if the initial bucket creation fails.
- Always release claimed PoC resources immediately after the report is accepted or a reasonable reporting period has elapsed (e.g. 7 days with no response).
- Feed output from the `subdomain-enum` skill directly as `SECSKILL_SUBDOMAIN_LIST` for a complete recon-to-takeover pipeline.
- Nuclei takeover template reference: https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers
- subjack reference: https://github.com/haccer/subjack
