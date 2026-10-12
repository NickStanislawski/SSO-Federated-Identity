# Security controls

## Objective and implementation

The lab demonstrates trust validation and access denial while keeping fixtures separate from production authentication. RS256 JWT tests restrict accepted algorithms and require issuer/audience/expiry/subject/nonce/groups. Authlib's real client validates ID tokens using the trusted issuer's advertised JWKS and supported algorithms. Configure the trusted provider for RS256; the static configuration checker alone does not enforce a remote provider's settings.

SAML pins the configured certificate instead of trusting embedded attacker certificates, allows RSA-SHA256/SHA256, expects the signature directly under the assertion, verifies the referenced element, and consumes only verified attributes. XML entities and DTD input are rejected; request decompression and POST size are bounded. Negative tests cover tampering, wrong certificate, duplicate assertions and replay.

## Sessions and deployment boundary

Only an opaque session handle is in the signed browser cookie. Session data stays server-side in memory; cookie secrets regenerate on restart. Cookies are HttpOnly. HTTPS mode uses Secure cookies. OIDC uses SameSite=Lax; SAML's cross-site POST requires SameSite=None with Secure on HTTPS. The loopback lab works with same-site loopback hosts and is not suitable for remote deployment. Responses use no-store, nosniff and a restrictive CSP. The Flask development servers are local lab services.

Audit records omit query strings, authorization codes, tokens, assertions, cookies and personal names. Built-in request URL logging is disabled in the launcher/tests to avoid code leakage. Reverse proxies must follow the same redaction rule. The synthetic client secret is an intentional public fixture and grants nothing outside the local automatic-sign-in provider. Signing private keys are generated in memory and not saved.

## MFA and contextual access

Optional OIDC require_mfa rejects tokens lacking an mfa authentication-method value, and this denial is tested. That is application enforcement of a context claim, not proof a real factor challenge happened. Okta policy enforcement, enrollment, contextual access and assurance semantics require tenant tests. Do not assume every provider encodes assurance with the same amr value.

## Remaining production requirements

Use managed persistent session/replay storage, bounded audit/cache retention, authenticated people, real MFA policy, approved role administration, protected keys, TLS termination, time synchronization and vetted protocol toolkits. The lab's used-ID set and pending/session stores do not provide distributed consistency or periodic cleanup. Configuration/state should be externalized for deployment. Certificate rotation and global logout are runbook work, not executed controls.

