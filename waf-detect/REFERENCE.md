# Reference: waf-detect

## WAF Fingerprint Pattern Table

Reference table for identifying specific WAF products from response headers and block-page characteristics.

| WAF Product | Identifying Headers | Block Response Characteristics |
|-------------|--------------------|---------------------------------|
| **Cloudflare** | `CF-RAY`, `Server: cloudflare` | 403/503 + "Cloudflare" in body, `__cf_bm` cookie |
| **AWS WAF** | `x-amzn-requestid`, `x-amz-cf-id` | 403 + "AWS" or "Request blocked" in body |
| **Akamai** | `X-Check-Cacheable`, `X-Akamai-*`, `Server: AkamaiGHost` | 403 + Reference # in body |
| **F5 BIG-IP ASM** | `X-WA-Info`, `Set-Cookie: TS` (cookie starting with `TS`) | Policy block page |
| **Sucuri** | `X-Sucuri-ID`, `Server: Sucuri/Cloudproxy` | 403 + Sucuri logo page |
| **ModSecurity** | `mod_security` in Server header (or no special header) | 403 + "ModSecurity" in body or custom error page |
