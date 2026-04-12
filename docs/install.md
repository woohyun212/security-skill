# 설치 가이드

## Claude Code

```bash
# 레포 클론
git clone https://github.com/YOUR_USERNAME/security-skill.git
cd security-skill

# 전체 스킬 설치
for dir in */; do
  [ -f "$dir/SKILL.md" ] && mkdir -p ~/.claude/skills/"$dir" && cp "$dir/SKILL.md" ~/.claude/skills/"$dir"
done
```

## 개별 스킬 설치

```bash
# 원하는 스킬만 복사
mkdir -p ~/.claude/skills/cve-lookup
cp cve-lookup/SKILL.md ~/.claude/skills/cve-lookup/
```

## 보안 도구 사전 설치

스킬이 위임하는 주요 보안 도구:

```bash
# Go 기반 도구
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Python 기반 도구
pip install pip-audit

# 시스템 패키지
sudo apt install nmap whois dnsutils openssl jq curl
```

## 환경 변수

일부 스킬은 API 키가 필요합니다. `~/.config/security-skill/secrets.env`에 설정:

```bash
mkdir -p ~/.config/security-skill
cat > ~/.config/security-skill/secrets.env << 'EOF'
# VirusTotal API (malware-hash 스킬)
SECSKILL_VT_API_KEY=your_key_here

# Shodan API (향후)
SECSKILL_SHODAN_API_KEY=your_key_here
EOF
chmod 600 ~/.config/security-skill/secrets.env
```
