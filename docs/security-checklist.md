# Security checklist

| Control | Local result | External requirement |
|---|---|---|
| Code + PKCE | HTTP round-trip and wrong-verifier rejection pass | Confirm provider client settings |
| State/nonce | Invalid state and nonce tests pass | Test proxy/cookie environment |
| Signature/issuer/audience/expiry | JWT and signed assertion tests pass | Pin approved issuer/trust, validate real artifacts |
| SAML replay/wrapping | Replay and duplicate assertion tests pass | Persistent distributed cache and toolkit review |
| Least privilege | Unknown roles denied | Governance for group administrators |
| Session/logout | Local CSRF logout and expiry pass | Global IdP/logout/token revocation tests |
| MFA | Missing context rejected | Real authenticator/policy test pending |
| Secrets/data | Ephemeral keys, sanitized fixtures | Tenant secret storage and log redaction |
| Certificate lifetime | Fixture 30-day threshold check passes | Execute operational rollover drill |
| Metadata | Static ACS consistency checked | Trusted remote metadata validation pending |
| Publication | Public archive excludes review/ | Git ignore/history/secret review pending |
