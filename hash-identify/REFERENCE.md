# Reference: hash-identify

## Hash Length Reference Table

Maps algorithm names to their hex-encoded output lengths and example partial outputs (computed from input `"test"`).

| Algorithm | Length (hex chars) | Example output (partial) |
|-----------|--------------------|--------------------------|
| MD5 | 32 | `098f6bcd4621d373cade4e83...` |
| SHA-1 | 40 | `a94a8fe5ccb19ba61c4c0873...` |
| SHA-224 | 56 | `90a3ed9e32b2aaf4c61c410e...` |
| SHA-256 | 64 | `9f86d081884c7d659a2feaa0...` |
| SHA-384 | 96 | `768412320f7b0aa5812fce42...` |
| SHA-512 | 128 | `ee26b0dd4af7e749aa1a8ee3...` |
| SHA3-256 | 64 | `36f028580bb02cc8272a9a02...` |
| SHA3-512 | 128 | `9ece086e9bac491fac5c1d107...` |
| BLAKE2b | 128 | `a71079d42853dea26e453004...` |
| BLAKE2s | 64 | `f308fc02ce9172ad02a7d75a...` |

## Verification Candidate Mapping

Maps hash length to algorithm candidates used during plaintext verification.

| Hash length (hex chars) | Algorithm candidates |
|-------------------------|----------------------|
| 32 | `md5` |
| 40 | `sha1` |
| 56 | `sha224` |
| 64 | `sha256`, `sha3_256` |
| 96 | `sha384` |
| 128 | `sha512`, `sha3_512`, `blake2b`, `blake2s` |

Slow/salted hashes (bcrypt, Argon2, PBKDF2, PBKDF2-HMAC) are not covered by `hashlib` — use Hashcat for those.
