# DVJA Ground Truth — Known Vulnerabilities

Source: https://github.com/appsecco/dvja  
Used as: baseline to measure SAST skill precision and recall.  
Note: A9 (Vulnerable Components) is excluded — SCA is out of scope.

---

## GT-01 — SQL Injection

| Field | Value |
|---|---|
| OWASP (original) | A1 Injection |
| OWASP 2021 | A03:2021 |
| CWE | CWE-89 |
| File | `src/main/java/com/appsecco/dvja/services/UserService.java` |
| Pattern | String concatenation in JPQL query |
| Sink | `entityManager.createQuery("SELECT u FROM User u WHERE u.login = '" + login + "'")` |
| Source | `login` parameter from user input |
| Severity | Critical |

**Vulnerable code:**
```java
Query query = entityManager.createQuery("SELECT u FROM User u WHERE u.login = '" + login + "'");
```

---

## GT-02 — Command Injection

| Field | Value |
|---|---|
| OWASP (original) | A1 Injection |
| OWASP 2021 | A03:2021 |
| CWE | CWE-78 |
| File | `src/main/java/com/appsecco/dvja/controllers/PingAction.java` |
| Pattern | `Runtime.exec()` with unsanitized user input |
| Sink | `runtime.exec(command)` |
| Source | `getAddress()` — user-supplied IP/hostname |
| Severity | Critical |

**Vulnerable code:**
```java
String[] command = { "/bin/bash", "-c", "ping -t 5 -c 5 " + getAddress() };
Process process = runtime.exec(command);
```

---

## GT-03 — Insecure Password Reset (Predictable Token)

| Field | Value |
|---|---|
| OWASP (original) | A2 Broken Authentication |
| OWASP 2021 | A07:2021 |
| CWE | CWE-640 |
| File | `src/main/java/com/appsecco/dvja/controllers/ResetPassword.java` |
| Pattern | MD5 hash of username used as reset key |
| Sink | `resetPasswordExecute.action?login=<user>&key=<md5(user)>` |
| Source | User-controlled `login` and `key` parameters |
| Severity | High |

**Vulnerable logic:** Reset key is `md5(username)` — predictable and computable by any attacker.

---

## GT-04 — Weak Password Hashing (MD5, No Salt)

| Field | Value |
|---|---|
| OWASP (original) | A2 Broken Authentication |
| OWASP 2021 | A02:2021 |
| CWE | CWE-916 |
| File | `src/main/java/com/appsecco/dvja/services/UserService.java` |
| Pattern | `DigestUtils.md5DigestAsHex()` with no salt |
| Method | `hashEncodePassword()` |
| Severity | High |

**Vulnerable code:**
```java
private String hashEncodePassword(String password) {
    return DigestUtils.md5DigestAsHex(password.getBytes());
}
```

---

## GT-05 — Reflected XSS

| Field | Value |
|---|---|
| OWASP (original) | A3 Cross-site Scripting |
| OWASP 2021 | A03:2021 |
| CWE | CWE-79 |
| File | `src/main/webapp/WEB-INF/content/listProduct.jsp` |
| Pattern | `request.getParameter()` rendered directly into HTML |
| Sink | `<%= request.getParameter("searchQuery") %>` |
| Source | `searchQuery` URL parameter |
| Severity | High |

---

## GT-06 — Stored XSS (Output Encoding Disabled)

| Field | Value |
|---|---|
| OWASP (original) | A3 Cross-site Scripting |
| OWASP 2021 | A03:2021 |
| CWE | CWE-79 |
| File | `src/main/webapp/WEB-INF/content/listProduct.jsp` |
| Pattern | Struts2 `<s:property escape="false"/>` on untrusted data |
| Sink | `<s:property value="name" escape="false"/>` |
| Source | Product name from database (user-supplied during product creation) |
| Severity | High |

---

## GT-07 — Insecure Direct Object Reference (IDOR)

| Field | Value |
|---|---|
| OWASP (original) | A4 Insecure Direct Object Reference |
| OWASP 2021 | A01:2021 |
| CWE | CWE-639 |
| File | `src/main/java/com/appsecco/dvja/controllers/UserAction.java` |
| Method | `editUser()` |
| Pattern | No authorization check — any user can edit any userId |
| Severity | High |

**Vulnerable code:**
```java
user = userService.find(getUserId());
user.setPassword(getPassword());
userService.save(user);
// Missing: check that getUserId() == session user's id
```

---

## GT-08 — Security Misconfiguration (Dev Mode + Null Dereference)

| Field | Value |
|---|---|
| OWASP (original) | A5 Security Misconfiguration |
| OWASP 2021 | A05:2021 |
| CWE | CWE-209 (error info leak), CWE-476 (null dereference) |
| Files | `src/main/resources/struts.xml`, `src/main/java/com/appsecco/dvja/controllers/ApiAction.java` |
| Pattern 1 | `struts.devMode = true` exposes stack traces |
| Pattern 2 | No null check before `user.getEmail()` in `ApiAction.ping()` |
| Severity | Medium |

---

## GT-09 — Sensitive Data in Logs (Password Logged)

| Field | Value |
|---|---|
| OWASP (original) | A6 Sensitive Data Exposure |
| OWASP 2021 | A09:2021 |
| CWE | CWE-532 |
| File | `src/main/java/com/appsecco/dvja/services/UserService.java` |
| Method | `resetPasswordByLogin()` |
| Pattern | Plaintext password written to application log |
| Severity | High |

**Vulnerable code:**
```java
logger.info("Changing password for login: " + login + " New password: " + password);
```

---

## GT-10 — Missing Function Level Access Control (Cookie-based Admin)

| Field | Value |
|---|---|
| OWASP (original) | A7 Missing Function Level Access Control |
| OWASP 2021 | A01:2021 |
| CWE | CWE-285 |
| File | `src/main/java/com/appsecco/dvja/controllers/ApiAction.java` |
| Method | `adminShowUsers()` |
| Pattern | Admin check trusts client-supplied cookie value |
| Severity | Critical |

**Vulnerable code:**
```java
for(Cookie c: getServletRequest().getCookies()) {
    if(c.getName().equals("admin") && c.getValue().equals("1")) {
        isAdmin = true;
    }
}
```

---

## GT-11 — CSRF (Missing Anti-CSRF Token)

| Field | Value |
|---|---|
| OWASP (original) | A8 Cross-site Request Forgery |
| OWASP 2021 | A01:2021 |
| CWE | CWE-352 |
| File | Add/Edit Product form (`addEditProduct.action`) |
| Pattern | No CSRF token in state-changing form submission |
| Severity | Medium |
| Static detectability | Low — requires checking Struts2 interceptor config, not a code pattern |

---

## GT-12 — Unvalidated Redirect

| Field | Value |
|---|---|
| OWASP (original) | A10 Unvalidated Redirects and Forwards |
| OWASP 2021 | A01:2021 |
| CWE | CWE-601 |
| File | `src/main/java/com/appsecco/dvja/controllers/RedirectAction.java` |
| Method | `execute()` |
| Pattern | User-controlled URL passed directly to redirect |
| Severity | Medium |

**Vulnerable code:**
```java
public String execute() {
    if(!StringUtils.isEmpty(getUrl()))
        return "redirect";  // url comes from user input, no validation
}
```

---

## Summary Table

| ID | CWE | OWASP 2021 | File | Severity | Statically Detectable |
|---|---|---|---|---|---|
| GT-01 | CWE-89 | A03 | UserService.java | Critical | Yes |
| GT-02 | CWE-78 | A03 | PingAction.java | Critical | Yes |
| GT-03 | CWE-640 | A07 | ResetPassword.java | High | Yes |
| GT-04 | CWE-916 | A02 | UserService.java | High | Yes |
| GT-05 | CWE-79 | A03 | listProduct.jsp | High | Yes |
| GT-06 | CWE-79 | A03 | listProduct.jsp | High | Yes |
| GT-07 | CWE-639 | A01 | UserAction.java | High | Partial |
| GT-08 | CWE-209 | A05 | ApiAction.java / struts.xml | Medium | Yes |
| GT-09 | CWE-532 | A09 | UserService.java | High | Yes |
| GT-10 | CWE-285 | A01 | ApiAction.java | Critical | Yes |
| GT-11 | CWE-352 | A01 | (form config) | Medium | Low |
| GT-12 | CWE-601 | A01 | RedirectAction.java | Medium | Yes |

**Total: 12 vulnerabilities across 9 files**  
**Statically detectable by SAST: 10 confidently, 1 partial (GT-07), 1 low (GT-11)**

---

## How to Use This File

When `/sast:find-vulns` produces output, compare each finding against this table:
- **True Positive (TP):** Finding matches a GT entry (file + CWE)
- **False Positive (FP):** Finding has no matching GT entry
- **False Negative (FN):** GT entry has no matching finding

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
```

Target: Recall ≥ 0.8 on statically detectable findings before moving to Milestone 3.
