---
name: subdomain-enum
description: Subdomain enumeration using subfinder and amass to discover attack surface
license: MIT
metadata:
  category: recon
  locale: en
  phase: v1
---

## What this skill does

Enumerates subdomains of a target domain using subfinder and amass. Collects results from multiple sources (Certificate Transparency, DNS brute-force, passive databases, etc.), merges and deduplicates them, then validates live hosts using httpx.

## When to use

- During the initial reconnaissance phase of a penetration test to map the attack surface
- When defining the scope for a bug bounty target
- When periodically auditing an organization's exposed subdomain inventory

## Prerequisites

- Go 1.21 or later installed
- Install subfinder:
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
- Install amass (optional):
  ```bash
  go install -v github.com/owasp-amass/amass/v4/...@master
  ```
- Install httpx (for live host validation):
  ```bash
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
- Environment variable `SECSKILL_TARGET_DOMAIN`: target domain (e.g. `example.com`)
- Environment variable `SECSKILL_OUTPUT_DIR`: directory for saving results (default: `./output`)

## Inputs

| Variable | Required | Description |
|----------|----------|-------------|
| `SECSKILL_TARGET_DOMAIN` | required | Root domain to enumerate |
| `SECSKILL_OUTPUT_DIR` | optional | Path to save result files (default: `./output`) |
| `SECSKILL_USE_AMASS` | optional | Set to `true` to also run amass (default: `false`) |

## Workflow

### Step 1: Prepare environment

```bash
export TARGET="${SECSKILL_TARGET_DOMAIN:?Set the SECSKILL_TARGET_DOMAIN environment variable}"
export OUTDIR="${SECSKILL_OUTPUT_DIR:-./output}"
mkdir -p "$OUTDIR"
echo "[*] Target domain: $TARGET"
echo "[*] Output directory: $OUTDIR"
```

### Step 2: Run subfinder

```bash
echo "[*] Running subfinder..."
subfinder -d "$TARGET" \
  -silent \
  -o "$OUTDIR/subfinder_${TARGET}.txt"
echo "[+] subfinder complete: $(wc -l < "$OUTDIR/subfinder_${TARGET}.txt") results"
```

### Step 3: Run amass (optional)

```bash
if [ "${SECSKILL_USE_AMASS:-false}" = "true" ]; then
  echo "[*] Running amass (this may take a while)..."
  amass enum -passive -d "$TARGET" \
    -o "$OUTDIR/amass_${TARGET}.txt"
  echo "[+] amass complete: $(wc -l < "$OUTDIR/amass_${TARGET}.txt") results"
else
  echo "[*] Skipping amass (enable with SECSKILL_USE_AMASS=true)"
fi
```

### Step 4: Merge results and deduplicate

```bash
echo "[*] Merging results..."
cat "$OUTDIR"/subfinder_*.txt "$OUTDIR"/amass_*.txt 2>/dev/null \
  | sort -u \
  > "$OUTDIR/all_subdomains_${TARGET}.txt"
TOTAL=$(wc -l < "$OUTDIR/all_subdomains_${TARGET}.txt")
echo "[+] Total subdomains after deduplication: $TOTAL"
```

### Step 5: Validate live hosts with httpx

```bash
echo "[*] Validating live hosts..."
httpx -l "$OUTDIR/all_subdomains_${TARGET}.txt" \
  -silent \
  -status-code \
  -title \
  -tech-detect \
  -o "$OUTDIR/live_subdomains_${TARGET}.txt"
LIVE=$(wc -l < "$OUTDIR/live_subdomains_${TARGET}.txt")
echo "[+] Live hosts: $LIVE"
echo "[+] Results saved to: $OUTDIR/live_subdomains_${TARGET}.txt"
```

### Step 6: Print summary

```bash
echo ""
echo "===== Subdomain Enumeration Summary ====="
echo "Target domain : $TARGET"
echo "Total found   : $TOTAL"
echo "Live hosts    : $LIVE"
echo "Output files  : $OUTDIR/"
echo "========================================="
```

## Done when

- `all_subdomains_${TARGET}.txt` is created and contains at least one entry
- `live_subdomains_${TARGET}.txt` is created
- Each step exits with code 0

## Failure modes

| Symptom | Cause | Resolution |
|---------|-------|------------|
| `subfinder: command not found` | Not installed | Check Go PATH and reinstall |
| 0 results | Invalid domain or network blocked | Verify domain, test DNS connectivity |
| httpx timeout | Network latency | Adjust with `-timeout` flag |
| amass taking too long | Active enumeration mode | Use `-passive` flag or disable amass |

## Notes

- Only use against domains for which you have **prior written authorization**.
- Adding API keys for subfinder in `~/.config/subfinder/provider-config.yaml` yields more results (Shodan, Censys, VirusTotal, etc.).
- amass can run for a long time; setting a timeout (`-timeout 30`) is recommended.
- Result files can be used as input for the `port-scan` and `nuclei-scan` skills.
