# SafeVault – Activity 3: Vulnerability Summary

## Vulnerabilities Identified

### 1. SQL Injection (VulnerableCode.cs – GetUserVulnerable, LoginVulnerable)
**Problem:** User input was concatenated directly into SQL strings.
```csharp
// ❌ Vulnerable
string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
```
An attacker could input `' OR '1'='1` to bypass login, or `'; DROP TABLE Users;--` to destroy data.

**Fix:** Replace with parameterized queries. User input is passed as a typed `SqlParameter` — the SQL engine treats it as data only, never as executable code.
```csharp
// ✅ Fixed
const string query = "SELECT * FROM Users WHERE Username = @Username";
cmd.Parameters.Add("@Username", SqlDbType.NVarChar, 100).Value = username;
```

---

### 2. Cross-Site Scripting / XSS (VulnerableCode.cs – RenderGreetingVulnerable)
**Problem:** User-supplied values were written raw into HTML output.
```csharp
// ❌ Vulnerable
return "<h1>Welcome, " + username + "!</h1>";
```
An attacker could input `<script>alert('XSS')</script>` and the script would execute in every visitor's browser.

**Fix:** HTML-encode all user values before rendering with `HttpUtility.HtmlEncode()`. This converts `<` → `&lt;`, `>` → `&gt;`, etc., so the browser displays the text instead of executing it.
```csharp
// ✅ Fixed
string safeUsername = HttpUtility.HtmlEncode(username);
return "<h1>Welcome, " + safeUsername + "!</h1>";
```

---

### 3. Missing Input Validation (VulnerableCode.cs – LoginVulnerable)
**Problem:** No length or format checks before using input in queries. Extremely long inputs could cause unexpected behaviour.

**Fix:** Validate all inputs with `ValidationHelpers` (Activity 1) before any database call. Reject anything that doesn't match expected format, length, or character set.

---

## Fixes Applied

| File | Change |
|---|---|
| `SecureCode.cs` | Parameterized queries replace all string-concatenated SQL |
| `SecureCode.cs` | `HttpUtility.HtmlEncode()` applied before any HTML output |
| `SecureCode.cs` | `ValidationHelpers.IsValidUsername()` called before DB access |
| `TestDebugAndFixes.cs` | 10 tests confirm attacks are blocked and clean inputs still work |

---

## Test Results (Expected)

| Test | Expected Result |
|---|---|
| SQL injection payloads in username | ❌ Rejected by `IsValidUsername()` |
| XSS payloads in output | ✅ Encoded by `HtmlEncode()` — not executed |
| XSS payloads detected pre-output | ✅ Caught by `ContainsXSS()` |
| Oversized input (101 chars) | ❌ Rejected |
| Null input | ❌ Rejected |
| Valid username / email | ✅ Accepted — no regression |

---

## Complete Project File Structure

```
SafeVault/
├── webform.html                        ← Activity 1: Secure HTML form
├── database.sql                        ← Activity 1: Parameterized schema
├── Helpers/
│   └── ValidationHelpers.cs           ← Activity 1: Input validation & XSS detection
├── Data/
│   └── UserRepository.cs              ← Activity 1: Parameterized DB queries
├── Models/
│   └── User.cs                        ← Activity 2: User model + Roles constants
├── Auth/
│   └── AuthService.cs                 ← Activity 2: BCrypt hashing + JWT
├── Controllers/
│   └── AuthController.cs              ← Activity 2: Login, register, RBAC endpoints
├── Debug/
│   ├── VulnerableCode.cs              ← Activity 3: Insecure examples (before)
│   └── SecureCode.cs                  ← Activity 3: Fixed examples (after)
└── Tests/
    ├── TestInputValidation.cs         ← Activity 1: SQL injection & XSS tests
    ├── TestAuthAndAuthorization.cs    ← Activity 2: Auth & RBAC tests
    └── TestDebugAndFixes.cs           ← Activity 3: Regression & attack tests
```
