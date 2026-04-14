---
name: whois-lookup
description: Domain and IP WHOIS lookup to gather registration and ownership information
license: MIT
metadata:
  category: recon
  locale: en
  phase: v1
---

## What this skill does

Uses the `whois` command to query registration information for a domain or IP address. Parses and organizes key fields — registrar/registrant info, registration/expiry dates, name servers, IP ranges (CIDR) — and outputs them in a report format.

## When to use

- When verifying domain ownership and registrar
- When assessing takeover potential based on domain expiry dates
- When identifying the ASN and organization associated with an IP address
- When exploring related IP ranges (CIDR) to discover additional attack surface

## Prerequisites

- Install the `whois` command:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install -y whois
  # CentOS/RHEL
  sudo yum install -y whois
  ```
- Environment variable `SECSKILL_TARGET`: domain or IP address to look up

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET` | required | Domain or IP address to look up |
| `SECSKILL_OUTPUT_DIR` | optional | Directory for saving results (default: `./output`) |

## Workflow

### Step 1: Prepare environment and detect input type

```bash
export TARGET="${SECSKILL_TARGET:?Set the SECSKILL_TARGET environment variable (domain or IP)}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"

# Detect IPv4/IPv6
if echo "$TARGET" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
  TARGET_TYPE="ipv4"
elif echo "$TARGET" | grep -qE '^[0-9a-fA-F:]+:[0-9a-fA-F:]+$'; then
  TARGET_TYPE="ipv6"
else
  TARGET_TYPE="domain"
fi

echo "[*] Target: $TARGET (type: $TARGET_TYPE)"
SAFE_NAME=$(echo "$TARGET" | tr '/' '_')
OUTFILE="$OUTDIR/whois_${SAFE_NAME}.txt"
```

### Step 2: Run WHOIS query and save raw output

```bash
echo "[*] Running WHOIS lookup..."
echo "===== WHOIS Raw Data: $TARGET =====" > "$OUTFILE"
echo "Query time: $(date -u '+%Y-%m-%dT%H:%M:%SZ')" >> "$OUTFILE"
echo "" >> "$OUTFILE"

whois "$TARGET" 2>/dev/null >> "$OUTFILE"

if [ $? -ne 0 ] || [ ! -s "$OUTFILE" ]; then
  echo "[-] WHOIS lookup failed or returned no results"
  exit 1
fi
echo "[+] Raw WHOIS data saved: $OUTFILE"
```

### Step 3: Parse key fields for domain targets

```bash
if [ "$TARGET_TYPE" = "domain" ]; then
  echo ""
  echo "===== Domain WHOIS Summary ====="

  REGISTRAR=$(grep -iE "Registrar:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  CREATED=$(grep -iE "Creation Date:|Created:|Registered:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  EXPIRES=$(grep -iE "Expiry Date:|Expiration Date:|Expires:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  UPDATED=$(grep -iE "Updated Date:|Last Modified:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  STATUS=$(grep -iE "Domain Status:" "$OUTFILE" | head -3 | cut -d':' -f2- | xargs | tr '\n' ', ')
  NS=$(grep -iE "Name Server:" "$OUTFILE" | cut -d':' -f2- | xargs | tr ' ' '\n' | sort -u | tr '\n' ' ')
  REGISTRANT=$(grep -iE "Registrant Organization:|Registrant Name:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  REGISTRANT_EMAIL=$(grep -iE "Registrant Email:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)

  echo "Registrar       : ${REGISTRAR:-(not available)}"
  echo "Registrant      : ${REGISTRANT:-(privacy protected)}"
  echo "Registrant email: ${REGISTRANT_EMAIL:-(redacted)}"
  echo "Created         : ${CREATED:-(not available)}"
  echo "Expires         : ${EXPIRES:-(not available)}"
  echo "Last updated    : ${UPDATED:-(not available)}"
  echo "Domain status   : ${STATUS:-(not available)}"
  echo "Name servers    : ${NS:-(not available)}"
  echo "==============================="
fi
```

### Step 4: Parse key fields for IP targets

```bash
if [ "$TARGET_TYPE" = "ipv4" ] || [ "$TARGET_TYPE" = "ipv6" ]; then
  echo ""
  echo "===== IP WHOIS Summary ====="

  NETRANGE=$(grep -iE "NetRange:|inetnum:|CIDR:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  CIDR=$(grep -iE "CIDR:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  NETNAME=$(grep -iE "NetName:|netname:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ORGNAME=$(grep -iE "OrgName:|org-name:|owner:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  COUNTRY=$(grep -iE "Country:|country:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ASN=$(grep -iE "OriginAS:|origin:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)
  ABUSE=$(grep -iE "OrgAbuseEmail:|abuse-mailbox:" "$OUTFILE" | head -1 | cut -d':' -f2- | xargs)

  echo "IP range     : ${NETRANGE:-(not available)}"
  echo "CIDR         : ${CIDR:-(not available)}"
  echo "Network name : ${NETNAME:-(not available)}"
  echo "Organization : ${ORGNAME:-(not available)}"
  echo "Country      : ${COUNTRY:-(not available)}"
  echo "ASN          : ${ASN:-(not available)}"
  echo "Abuse email  : ${ABUSE:-(not available)}"
  echo "========================="
fi
```

### Step 5: Look up IP range from domain A record (domain targets only)

```bash
if [ "$TARGET_TYPE" = "domain" ]; then
  echo ""
  echo "[*] Looking up IP range from domain A record..."
  IP=$(dig "$TARGET" A +short 2>/dev/null | head -1)
  if [ -n "$IP" ]; then
    echo "[*] Resolved IP: $IP - running WHOIS..."
    whois "$IP" 2>/dev/null \
      | grep -iE "NetRange:|inetnum:|CIDR:|OrgName:|org-name:" \
      | head -10 \
      | tee -a "$OUTFILE"
  else
    echo "[-] No A record found"
  fi
fi
```

## Done when

- Raw WHOIS data is saved to a file
- Key fields (registrar, dates, name servers or IP range, organization) are parsed and displayed
- Output file path is shown

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `whois: command not found` | Not installed | Run `apt-get install whois` |
| Empty results | WHOIS server not responding | Try manually: `whois -h whois.iana.org $TARGET` |
| No info due to privacy protection | GDPR/Privacy Shield applied | Expected. Use other reconnaissance methods |
| Rate limit error | Too many requests | Wait and retry |

## Notes

- Domains with upcoming expiry dates should be further evaluated for domain takeover potential.
- Since GDPR, registrant information for many domains is redacted.
- IP range data can be used to define the scope for additional scans.
- Results can be chained with the `port-scan` skill.
