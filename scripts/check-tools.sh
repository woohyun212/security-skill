#!/usr/bin/env bash
# Pre-flight tool availability check
REQUIRED_TOOLS="nmap nuclei dig curl openssl subfinder wafw00f trufflehog gitleaks trivy syft python3 git jq"
missing=0
for tool in $REQUIRED_TOOLS; do
  if command -v "$tool" &>/dev/null; then
    echo "[✓] $tool"
  else
    echo "[✗] $tool — MISSING"
    missing=$((missing + 1))
  fi
done
echo ""
echo "$missing tool(s) missing out of $(echo $REQUIRED_TOOLS | wc -w) required."
[ "$missing" -eq 0 ] && exit 0 || exit 1
