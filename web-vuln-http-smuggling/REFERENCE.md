# Reference: web-vuln-http-smuggling

## Impact Assessment

### Impact Chains

| Impact | Severity | Description |
|--------|----------|-------------|
| Request hijacking | Critical | Prepend smuggled request to victim's next request — steal their session/credentials |
| WAF bypass | High | Smuggle a request that bypasses the WAF's inspection of the "real" request body |
| Cache poisoning | High | Poison a cacheable response with attacker content — stored XSS at scale |
| Credential theft | Critical | Smuggle a GET to a page that reflects a request header containing victim cookies |

### Severity Mappings by Variant

| Variant confirmed | Severity |
|-------------------|----------|
| CL.TE | Critical (lowest dup rate, highest payout) |
| TE.CL | Critical |
| TE.TE | High/Critical (depends on exploitability) |
| H2.CL | Critical (modern stacks, often unpatched) |
| Timing signal only | Medium (submit with timing evidence, note unconfirmed) |

## Proxy Fingerprinting Indicators

Header-to-vendor mappings from Step 1 architecture fingerprinting:

| Response Header | Vendor / Layer |
|----------------|----------------|
| `Via: 1.1 vegur` | Heroku |
| `X-Cache: HIT` | Caching layer present |
| `CF-Ray:` | Cloudflare |
| `X-Amz-Cf-Id:` | AWS CloudFront |
| `X-Served-By:` | Fastly / Varnish |
| `Server: nginx` + `X-Powered-By: Express` | Nginx front-end + Node.js back-end |
