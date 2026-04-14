# Reference: web-vuln-mfa-bypass

## Severity Guide and Remediation

### Severity Classifications (9 levels)

| Severity | Bypass Type |
|----------|-------------|
| CRITICAL | Direct page navigation bypasses MFA — complete authentication bypass |
| CRITICAL | Response manipulation accepted by server — MFA bypass for any account |
| HIGH | No rate limiting on OTP — brute force of 6-digit TOTP feasible (1,000,000 combinations) |
| HIGH | OTP reuse allowed — stolen OTP valid multiple times |
| HIGH | Race condition — concurrent requests allow OTP use before invalidation |
| HIGH | MFA can be disabled without re-verification — social engineering + MFA removal |
| MEDIUM | Backup codes not rate-limited — slow brute force possible |
| MEDIUM | MFA state stored in client-side cookie without integrity check |
| LOW | Predictable/default OTP values accepted |

### Remediation Checklist

- Enforce server-side rate limiting (5–10 attempts max) with exponential backoff on OTP endpoint
- Invalidate OTP immediately upon first use; reject replay within the same TOTP window
- Validate MFA completion server-side before granting access to any post-MFA resource
- Use optimistic locking or atomic server-side state transitions to prevent race conditions
- Require current password or valid OTP before allowing MFA disable/change
- Never store MFA state in client-side cookies or localStorage
- Apply same rate limiting to backup codes as to primary OTP
