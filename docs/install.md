# Installation Guide

## Claude Code

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/security-skill.git
cd security-skill

# Install all skills
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

## Install Individual Skills

```bash
# Copy only the skill you want
mkdir -p ~/.claude/skills/cve-lookup
cp cve-lookup/SKILL.md ~/.claude/skills/cve-lookup/
```

## Pre-install Security Tools

Key security tools that skills delegate to:

```bash
# Go-based tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python-based tools
pip install pip-audit

# System packages
sudo apt install nmap whois dnsutils openssl jq curl
```

## Environment Variables

Some skills require API keys. Configure them in `~/.config/security-skill/secrets.env`:

```bash
mkdir -p ~/.config/security-skill
cat > ~/.config/security-skill/secrets.env << 'EOF'
# VirusTotal API (malware-hash skill)
SECSKILL_VT_API_KEY=your_key_here

# Shodan API (future use)
SECSKILL_SHODAN_API_KEY=your_key_here
EOF
chmod 600 ~/.config/security-skill/secrets.env
```
