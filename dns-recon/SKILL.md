---
name: dns-recon
description: DNS record reconnaissance and zone transfer attempts using dig, host, and nslookup
license: MIT
metadata:
  category: recon
  locale: en
  phase: v1
---

## What this skill does

Performs a full DNS record lookup on a target domain using dig, host, and nslookup. Enumerates A/AAAA/MX/NS/TXT/CNAME records, checks for zone transfer (AXFR) vulnerabilities, and verifies DNSSEC configuration.

## When to use

- When mapping a domain's infrastructure (mail servers, name servers, IP ranges)
- When detecting misconfigured DNS zone transfer vulnerabilities
- When auditing SPF/DKIM/DMARC configuration status
- When identifying subdomain takeover candidates

## Prerequisites

- Install the `dnsutils` package (includes dig, host, nslookup):
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y dnsutils
  # CentOS/RHEL
  sudo yum install -y bind-utils
  ```
- Environment variable `SECSKILL_TARGET_DOMAIN`: target domain

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET_DOMAIN` | required | Domain to query (e.g. `example.com`) |
| `SECSKILL_OUTPUT_DIR` | optional | Directory for saving results (default: `./output`) |
| `SECSKILL_DNS_RESOLVER` | optional | DNS resolver IP to use (default: system default) |

## Workflow

### Step 1: Prepare environment

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?Set the SECSKILL_TARGET_DOMAIN environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
export RESOLVER="${SECSKILL_DNS_RESOLVER:-}"
mkdir -p "$OUTDIR"
RESOLVER_OPT=""
[ -n "$RESOLVER" ] && RESOLVER_OPT="@${RESOLVER}"
echo "[*] Starting DNS recon: $TARGET"
```

### Step 2: Query basic records (A, AAAA, MX, NS, TXT, CNAME)

```bash
OUTFILE="$OUTDIR/dns_records_${TARGET}.txt"
echo "===== DNS Record Query: $TARGET =====" > "$OUTFILE"
echo "Query time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"
echo "" >> "$OUTFILE"

for RTYPE in A AAAA MX NS TXT CNAME SOA; do
  echo "--- ${RTYPE} record ---" | tee -a "$OUTFILE"
  dig $RESOLVER_OPT "$TARGET" "$RTYPE" +noall +answer 2>/dev/null \
    | tee -a "$OUTFILE"
  echo "" >> "$OUTFILE"
done

echo "[+] Basic record query complete"
```

### Step 3: Check email security records (SPF, DKIM, DMARC)

```bash
echo "--- Email security records ---" | tee -a "$OUTFILE"

echo "[SPF]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "$TARGET" TXT +short 2>/dev/null \
  | grep -i "v=spf" | tee -a "$OUTFILE"

echo "[DMARC]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "_dmarc.${TARGET}" TXT +short 2>/dev/null \
  | tee -a "$OUTFILE"

echo "[DKIM - default selector]" | tee -a "$OUTFILE"
dig $RESOLVER_OPT "default._domainkey.${TARGET}" TXT +short 2>/dev/null \
  | tee -a "$OUTFILE"

echo "[+] Email security record check complete"
```

### Step 4: Extract name servers and attempt zone transfer

```bash
echo "" >> "$OUTFILE"
echo "--- Zone Transfer (AXFR) Attempts ---" | tee -a "$OUTFILE"

NS_LIST=$(dig $RESOLVER_OPT "$TARGET" NS +short 2>/dev/null | sed 's/\.$//')
if [ -z "$NS_LIST" ]; then
  echo "[-] No name servers found." | tee -a "$OUTFILE"
else
  echo "$NS_LIST" | while read -r NS; do
    echo "[*] Attempting zone transfer from: $NS..." | tee -a "$OUTFILE"
    RESULT=$(dig @"$NS" "$TARGET" AXFR 2>/dev/null)
    if echo "$RESULT" | grep -q "Transfer failed\|connection refused\|REFUSED\|timed out"; then
      echo "[-] $NS: Zone transfer refused (expected)" | tee -a "$OUTFILE"
    elif echo "$RESULT" | grep -q "XFR size"; then
      echo "[!] $NS: Zone transfer succeeded! Vulnerability found" | tee -a "$OUTFILE"
      echo "$RESULT" >> "$OUTFILE"
    else
      echo "[-] $NS: No response or unknown result" | tee -a "$OUTFILE"
    fi
  done
fi
```

### Step 5: Check DNSSEC

```bash
echo "" >> "$OUTFILE"
echo "--- DNSSEC Check ---" | tee -a "$OUTFILE"

DNSKEY=$(dig $RESOLVER_OPT "$TARGET" DNSKEY +short 2>/dev/null)
DS=$(dig $RESOLVER_OPT "$TARGET" DS +short 2>/dev/null)

if [ -n "$DNSKEY" ] || [ -n "$DS" ]; then
  echo "[+] DNSSEC enabled" | tee -a "$OUTFILE"
  echo "DNSKEY: $DNSKEY" >> "$OUTFILE"
  echo "DS: $DS" >> "$OUTFILE"
else
  echo "[-] DNSSEC not configured" | tee -a "$OUTFILE"
fi

echo "[+] DNS recon complete: $OUTFILE"
```

### Step 6: Print summary

```bash
echo ""
echo "===== DNS Recon Summary ====="
echo "Target    : $TARGET"
echo "A records : $(dig $RESOLVER_OPT $TARGET A +short 2>/dev/null | tr '\n' ' ')"
echo "MX records: $(dig $RESOLVER_OPT $TARGET MX +short 2>/dev/null | tr '\n' ' ')"
echo "NS records: $(dig $RESOLVER_OPT $TARGET NS +short 2>/dev/null | tr '\n' ' ')"
echo "Output    : $OUTFILE"
echo "=============================="
```

## Done when

- All record types have been queried
- Zone transfer attempt results are recorded (regardless of success or failure)
- DNSSEC status has been verified
- Output file is created

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `dig: command not found` | dnsutils not installed | Run `apt-get install dnsutils` |
| All queries timing out | Firewall or DNS blocking | Specify a different resolver (`SECSKILL_DNS_RESOLVER=8.8.8.8`) |
| Zone transfer result empty | Correctly refused | Explore other attack vectors |
| NXDOMAIN response | Typo in domain or domain does not exist | Verify domain spelling |

## Notes

- If a zone transfer vulnerability is found, document it in the report immediately. This is a high-severity finding.
- TXT records may contain internal infrastructure hints and service authentication tokens.
- The `host -l` command can also be used for zone transfers: `host -l $TARGET $NAMESERVER`
- SPF `~all` or `+all` settings are vulnerable to spoofing and should be reported separately.
