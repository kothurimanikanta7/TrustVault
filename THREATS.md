# TrustVault Threat Architecture Profile (THREATS.md)

### 1. Threat: Stale Session Lifetime Exploits
* **Risk:** An access permission is revoked, but a viewer continues downloading files because their session token or cache remains valid for an hour.
* **Mitigation Strategy:** The backend completely bypasses client-side session state for document requests. The server re-evaluates the active permissions database records on every single transaction request, ensuring that revocation takes effect within milliseconds.
* **Status:** Fully Mitigated by Server Architecture.
