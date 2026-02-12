# Bookworms Online Security Report

## Summary
This report outlines the security features implemented for Bookworms Online membership registration, login, and account management.

## Implemented Controls
- **Secure registration and data storage**: Member data stored via EF Core (SQLite). Email uniqueness enforced. Credit card data encrypted using data protection.
- **Password security**: Passwords hashed using ASP.NET Core Identity `IPasswordHasher`. Strong password requirements enforced on client and server. Password history (last 2) prevents reuse. Min/max password age enforced.
- **Account protection**: Lockout after 3 failed login attempts with automatic recovery after lockout period.
- **Two-Factor Authentication**: One-time 2FA code required after password verification (development code displayed only in development).
- **Session management**: Cookie authentication with sliding expiration, session timeout, and single active session validation.
- **Anti-bot**: Google reCAPTCHA v3 integrated on registration, login, forgot password, and reset password.
- **File upload restrictions**: JPG-only uploads with size limits.
- **Audit logging**: Login, logout, registration, password changes, reset requests, and 2FA events recorded to the database.
- **CSRF/XSS**: Auto-validation for antiforgery tokens on POST and Razor encoding by default.
- **Error handling**: Custom 403 and 404 pages.

## Configuration Notes
- Add real reCAPTCHA keys in `appsettings.json`.
- Security policy settings in `Security` section can be adjusted for lockout durations, password age, and file upload limits.

## Testing Recommendations
- Register a member, verify unique email enforcement and JPG-only upload restrictions.
- Test password policy enforcement and password history checks.
- Verify lockout after repeated failed logins and automatic recovery after lockout duration.
- Validate 2FA flow (code displayed in development).
- Confirm session invalidation when logging in from another device.
