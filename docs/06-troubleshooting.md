# Troubleshooting

## Diagnosed build cases

**XML signature failed after embedding in Response.** Symptom: valid fixture signatures failed verification. Cause: inclusive canonicalization captured new ancestor namespaces when the signed Assertion was embedded. Fix: use exclusive XML canonicalization before signing. Verification: valid assertion and separate-app SAML round-trip pass; tampering still fails. Do not disable signature verification to fix formatting problems.

**Local HTTP requests blocked.** Symptom: loopback socket permission denied in restricted execution. Cause: host sandbox network boundary. Fix: perform authorized localhost tests in the permitted execution context. Verification: all HTTP integration tests pass; services shut down at suite end.

**MFA test setup failed.** Symptom: test server had no set_app() method. Cause: using a WSGI API unavailable in the installed Werkzeug server. Fix: replace and restore its app property inside the sequential test. Verification: missing MFA context is rejected and subsequent normal sign-in succeeds.

## Protocol diagnosis

Wrong redirect URI: compare exact callback string registered at IdP and sent by RP; do not broaden to a wildcard. State/nonce mismatch: verify browser session, issuer, and callback host; discard the failed flow and start again. Invalid signature: compare trusted key/certificate and signing algorithm; never accept embedded untrusted certificates. Audience mismatch: compare client ID or SP entity ID. SAML recipient mismatch: compare ACS and SubjectConfirmationData. Expired artifacts: check time synchronization and bounded clock-skew policy rather than disabling lifetime checks. Role denial: inspect verified groups and the least-privilege mapping; a valid login is not permission.

## Recovery and evidence

Restarting clears all local sessions, requests, authorization codes and replay IDs; signing keys rotate. Preserve sanitized failure evidence before restart. Token validity uses the validators' documented semantics; the SAML profile applies no clock skew and can be stricter than a production toolkit. Okta-specific troubleshooting should record sanitized request IDs/status only and consult its current diagnostics. No fabricated tenant logs are included.

