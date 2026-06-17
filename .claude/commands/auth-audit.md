Audit authentication protocol implementations — JWT, SAML, OAuth2, and OpenID Connect — for spec violations and logic bypass vulnerabilities. Reason against the relevant RFC/spec, not just known CVE patterns. Write structured findings to auth-findings.json.

Do NOT flag every `verify_signature=False` as a finding. Read the context. Reason about whether the unverified decode is used for a security decision or only for routing/error messages. Report only exploitable gaps.

## Background: Why This Skill Exists

Auth protocol bugs are invisible to pattern-based SAST because they require knowing the spec. A tool can flag `verify_aud=False` but cannot know whether that audience check matters in context. Claude can reason: "RFC 7523 §3 requires audience validation in JWT bearer assertions — this skips it, enabling token relay attacks."

This skill applies spec-level reasoning to auth implementation code.

## Input

`$ARGUMENTS` format: `[--repo <path>] [--lang <python|go|java|node>]`

- `--repo <path>` — path to repo root (default: current directory)
- `--lang <name>` — primary backend language (auto-detected if omitted)

## Step 1 — Detect Stack and Map Auth Surface

Detect language from file extensions. Then glob for files matching these patterns:

**Python:** `**/jwt*`, `**/token*`, `**/oauth*`, `**/saml*`, `**/auth*`, `**/session*`
**Go:** same patterns, `.go`
**Java:** same patterns, `.java`
**Node/TS:** same patterns, `.ts`, `.js`

Also search for imports/requires of known auth libraries:
- Python: `jwt`, `PyJWT`, `python-jose`, `authlib`, `onelogin`, `xmlsec`
- Go: `golang-jwt`, `lestrrat-go/jwx`, `dgrijalva/jwt-go`
- Java: `nimbus-jose-jwt`, `jjwt`, `opensaml`, `pac4j`
- Node: `jsonwebtoken`, `jose`, `passport`, `saml2-js`, `node-saml`

## Step 2 — The 6 Auth Vulnerability Classes

Internalize these before reading any file.

---

### Class 1 — JWT Signature and Claims Bypass (CWE-347)

JWT security depends on BOTH signature verification AND claims validation. Skipping either breaks the security model.

**Signature bypass patterns:**
- `decode(token, options={"verify_signature": False})` used for a security decision (not just key lookup)
- `verify=False` in any JWT library
- `algorithms=["none"]` or not specifying algorithms (allows none algorithm)
- Missing algorithm allowlist — library defaults may accept unexpected algorithms

**Claims bypass patterns:**
- `verify_aud=False` or `options={"verify_aud": False}` — enables token relay: a JWT issued for service B is accepted by service A
- `verify_exp=False` — expired tokens accepted indefinitely
- `verify_iss=False` — tokens from any issuer accepted
- Manual `exp` check missing or using wrong timezone (local vs UTC)
- `exp` check only done when field exists: `if "exp" in token: check()` — tokens with no `exp` never expire

**Algorithm confusion:**
- Algorithm taken from JWT header (`alg` field) without validation against expected algorithm
- RSA public key used as HMAC secret (classic confusion attack)
- `fallback_alg = header.get("alg")` used when JWK has no `alg` field

**For each JWT decode call found:**
1. Is `verify_signature` False? If yes — is the decoded value used for a security decision (auth, permissions, identity)?
2. Is `verify_aud` False? What is the context — is this a federated token endpoint where audience matters?
3. Is the algorithm list explicitly specified? Does it allow `"none"`?
4. Is `exp` checked, and if so — is it checked correctly (UTC, not just "if present")?
5. Is the `iss` (issuer) validated against an expected value?

---

### Class 2 — SAML Signature Verification Gaps (CWE-347)

SAML responses contain assertions about identity. Signature verification must be unconditional.

**Verification bypass patterns:**
- Signature check conditional on config: `if source.verification_kp and source.signed_assertion: verify()` — if `verification_kp` is None by default, verification never runs
- Checking signature only on response but not on assertion (or vice versa) — XML signature wrapping can move the signed element
- `verify_reference_uri` not checked — signature covers a different element than the assertion being used
- Using `defusedxml` to parse but `lxml` to act on (namespace confusion)

**XML Signature Wrapping (XSW):**
- After verification, code uses `root.find("Assertion")` to get assertion data
- But `_assertion` set during verification points to the verified (possibly moved) assertion
- If these diverge, the attacker's forged assertion is used

**Conditions bypass:**
- `NotBefore` / `NotOnOrAfter` not checked — expired assertions accepted
- `AudienceRestriction` not validated — assertion intended for IdP is accepted by SP

**For each SAML response processor found:**
1. Is signature verification conditional? What is the default config state?
2. Does the code verify BOTH response signature AND assertion signature where applicable?
3. After verification, which element is used for identity data — the verified `_assertion` or a fresh `root.find()`?
4. Are `NotBefore`, `NotOnOrAfter`, and `AudienceRestriction` validated?

---

### Class 3 — OAuth2 / OIDC Flow Violations (CWE-287)

OAuth2 security depends on correct implementation of several protocol elements.

**State parameter:**
- State not generated per-request → CSRF on authorization code flow
- State stored in session but not validated on callback
- State validated but not bound to a specific provider/client_id

**PKCE:**
- `code_challenge` present in auth request but not validated in token request
- Downgrade: token endpoint accepts code without `code_verifier` even when challenge was set
- Plain method accepted when S256 is expected

**Redirect URI:**
- Regex matching too broad: `^https://example\.com/` matches `https://example.com.attacker.com/`
- `fullmatch` vs `match` — `match` only checks start of string
- Protocol scheme not checked — `javascript:` URI accepted
- Open redirect via redirect_uri parameter before validation

**Token endpoint:**
- `client_secret` compared with `==` instead of constant-time compare (timing attack)
- `code` accepted from different `client_id` than it was issued to
- Authorization code reuse not prevented — code not deleted after use

**For each OAuth2 authorization and token endpoint found:**
1. Is state generated, stored, and validated? Is it bound to session?
2. Is PKCE enforced end-to-end — challenge stored at auth time, verified at token time?
3. Does redirect URI matching use `fullmatch` or anchored regex? Does it catch subdomain variants?
4. Is `client_secret` compared with constant-time compare?
5. Is the authorization code deleted after first use?

---

### Class 4 — Session and Identity Lifecycle (CWE-384)

**Session fixation:**
- Session ID not rotated after login — attacker who knows pre-auth session ID can hijack post-auth session
- Session not invalidated on logout

**Token lifetime:**
- Refresh tokens not revoked when access token is rotated
- No maximum session lifetime — refresh token never expires
- Token revocation endpoint exists but revocation not checked on use

**Identity federation:**
- User created from JWT/SAML claims without ownership check — can an attacker register a local account with the same identifier to take over a federated account (or vice versa)?
- Email from federated token trusted without domain restriction

**For each session/token management function found:**
1. Is session ID regenerated after successful authentication?
2. Is the old session destroyed on logout?
3. When a refresh token is rotated, is the previous one invalidated?
4. Can a local account and federated account collide on the same identifier?

---

### Class 5 — Cryptographic Weaknesses in Auth (CWE-916 / CWE-330)

**Weak algorithms:**
- Password hashed with MD5, SHA1, SHA256 without salt — flag for `bcrypt`/`argon2`/`PBKDF2`
- Token generated with `random()` or `time()` — must use `secrets.token_urlsafe()` or equivalent CSPRNG
- HMAC key too short (< 256 bits for HS256)
- EC key curve not validated before use

**For each password/token crypto operation:**
1. Is the hash algorithm resistant to brute force (bcrypt, argon2, PBKDF2 with ≥ 10k iterations)?
2. Is token generation using a CSPRNG?
3. For HMAC JWT: is the key long enough?

---

### Class 6 — Two-Step JWT Decode Pattern (CWE-285)

A common legitimate pattern: first decode without signature to get `kid`/`iss`, then look up the key, then verify. This pattern is only safe if:
- The unverified decode is ONLY used to find the verification key
- The actual identity/permission decision uses the VERIFIED decode result
- Even if key lookup fails (no matching key), access is DENIED not granted

**For each two-step decode pattern found:**
1. Is the unverified payload ever used for an identity or permission decision?
2. If no matching key is found — does the code deny access or fall through?
3. Is there a loop over multiple possible keys with no `break` — could an attacker succeed with one key while the code reports the wrong source?

---

## Step 3 — Build the Scan Queue

Priority order:
1. Files containing JWT decode/verify calls
2. Files containing SAML response processing
3. Files containing OAuth2 token endpoint logic
4. Files containing session creation/destruction
5. Files containing password hashing or token generation
6. Config/model files defining default values for `verification_kp`, `signed_assertion`, `verify_*` flags

## Step 4 — Analyze Each File

For every file, read it fully. Apply the relevant class analysis from Step 2.

**Critical check — default values:** For every boolean flag or nullable field that controls security behavior (e.g., `signed_assertion`, `verification_kp`, `require_pkce`), find its default value. If the default is the insecure state: finding.

**Critical check — conditional verification:** Any `if condition: verify()` pattern where the condition can be False by default or by misconfiguration is a finding.

## Step 5 — Score and Filter

**Confidence:**
- **0.90–1.00** — Spec violation clearly visible; default config is insecure; verification is skipped
- **0.70–0.89** — Violation likely but depends on how the value is used downstream
- **0.50–0.69** — Possible violation; requires knowing runtime config values
- **< 0.50** — Discard

Report ≥ 0.70. Report 0.50–0.69 with `"confidence_note"`.

**Number:** `AA-001`, `AA-002`, ...

**Severity:**

| Severity | Criteria |
|---|---|
| Critical | Signature verification skipped; any token accepted as valid identity |
| High | Audience/issuer not validated; token relay possible; PKCE downgrade |
| Medium | Expired token accepted; weak token generation; session fixation |
| Low | Timing-safe compare missing; missing AudienceRestriction check |

## Step 6 — Write auth-findings.json

```json
{
  "scanned_at": "<ISO 8601 timestamp>",
  "repo_path": "<absolute path>",
  "total_findings": 0,
  "findings_by_severity": { "critical": 0, "high": 0, "medium": 0, "low": 0 },
  "findings": [
    {
      "id": "AA-001",
      "class": "jwt-claims-bypass | saml-signature-gap | oauth2-violation | session-lifecycle | crypto-weakness | two-step-decode",
      "cwe": "CWE-347",
      "severity": "critical | high | medium | low",
      "confidence": 0.92,
      "confidence_note": "",
      "file": "authentik/providers/oauth2/views/token.py",
      "line": 418,
      "function": "__validate_jwt_from_source",
      "spec_reference": "RFC 7523 §3 — Authorization server MUST verify aud claim in JWT bearer assertions",
      "evidence": "options={\"verify_aud\": False}",
      "attack_scenario": "Attacker obtains a JWT signed by a federated source for a different audience (e.g. service B). Submits it to this token endpoint. Server accepts it because audience is not validated. Attacker receives access tokens for service A.",
      "description": "Audience claim is not validated when verifying JWT bearer assertions in the client_credentials flow. RFC 7523 requires the authorization server to verify the aud claim identifies it as an intended audience.",
      "fix_hint": "Remove verify_aud: False. The aud claim should equal the token endpoint URL of this authorization server."
    }
  ],
  "skipped_files": [],
  "warnings": []
}
```

## Hard Rules

- Do not flag `verify_signature=False` used only inside an exception handler to provide a better error message — check whether the result influences any security decision.
- Do not flag a two-step decode pattern if the verified result is used for identity and the unverified is only used for key lookup.
- `spec_reference` must name the specific RFC section or spec clause, not just "RFC 7523".
- `attack_scenario` must be concrete and realistic.

## Completion

```
auth-audit complete.
  Repo       : <repo_path>
  Lang       : <language>
  Files scanned : <N>
  Findings   : <total> (<critical> critical / <high> high / <medium> medium / <low> low)
  Output     : auth-findings.json
```
