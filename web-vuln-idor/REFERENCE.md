# Reference: web-vuln-idor

## Impact Classification and Chain Escalation

```
IDOR Impact Classification:
  Read PII (name, email, address)         -> Medium
  Read financial data (orders, payments)  -> High
  Write/modify another user's data        -> High
  Change another user's email/password    -> Critical (ATO)
  Access admin endpoint                   -> Critical (privilege escalation)

Chain escalation paths:
  IDOR + read email address  -> phishing / credential stuffing
  IDOR + write email field   -> ATO (change victim email, trigger password reset)
  IDOR + admin endpoint      -> escalate to admin ATO
  IDOR + PII at scale        -> prove mass data exposure (loop 20 IDs)
  IDOR + chatbot context     -> AI reads other users' conversation history
```
