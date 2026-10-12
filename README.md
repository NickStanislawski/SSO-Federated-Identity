# SSO & Federated Identity Engineering

## 1. Project Overview

Separate runnable local OIDC and SAML applications demonstrate federation engineering and security automation. Local sign-in is synthetic; Okta deployment and real MFA remain pending.

## 2. Objectives

Demonstrate Authorization Code + S256 PKCE, signed SAML assertions, role mapping, signature/claim validation, negative testing, repeatable security checks and sanitized evidence. Track the original nine acceptance criteria in PROJECT-STATUS.md.

## 3. Architecture

Browser → independent OIDC/SAML apps → local fixture IdP or future Okta → verified identity → application role/session. See [architecture](docs/01-architecture.md) and [protocol flows](docs/flows.md).

## 4. Technologies Used

Python 3.12 tested; Flask 3.1.3, Authlib 1.8.0, SignXML 5.1.0, PyJWT 2.15.1, cryptography 50.0.2, lxml 6.1.3, requests 2.34.2. See requirements.txt.

## 5. Key Features

Implemented and tested locally: separate sign-ins, PKCE, signed JWT/XML, state/nonce correlation, claim checks, role denial, SAML replay rejection, local logout/expiry, configuration checks and event reports. Planned: external provider integration, real MFA/contextual policy and global logout.

## 6. Implementation Summary

[Setup and launch](docs/02-environment-setup.md); `python scripts/run_lab.py` starts loopback apps. [Implementation](docs/03-implementation.md) explains canonical source. [Okta runbook](docs/okta-integration.md) covers pending tenant work.

## 7. Security Considerations

Automatic fixture sign-in is for education only. Private keys are ephemeral. Apps enforce verified claim mappings and server sessions. External deployment requires TLS and production protocol/session controls. See [security](docs/04-security-controls.md).

## 8. Testing and Validation

All 37 tests passed, including separate HTTP sign-in round-trips, bad signatures, wrong issuer/audience, replay, role denial and local session termination. Seven configuration checks passed. [Test log](tests/results.txt) · [Matrix](tests/TEST-MATRIX.md) · [Security report](data/evidence/security-report.json).

## 9. Results

Recorded 20 sanitized application HTTP events: 14 successes, 5 access denials, 1 failure. Success responses include redirects; this is not a count of authenticated users. Seven of nine acceptance criteria are demonstrated in local scope; MFA and complete tenant/screenshot evidence remain pending.

## 10. Challenges and Lessons Learned

Fixed assertion canonicalization after embedding and corrected the MFA test server setup; authorized network context enabled localhost tests. Consume verified elements and distinguish context claims from actual factor enforcement. See [troubleshooting](docs/06-troubleshooting.md).

## 11. Project Limitations

No Okta tenant validation, real factor challenge, conditional access execution, IdP-event correlation, global logout, encrypted assertions, production storage or browser screenshots. Local IdP automatically selects a fictional identity. Custom SAML supports a restricted profile. Public GitHub publication pending.

## 12. Future Improvements

Planned: authenticated provider, persistent session/replay stores, standardized production SAML toolkit, tenant event collection, assurance-policy evidence, rollover drill, Project 1 adapter and publication review.

## 13. Documentation and Evidence

- [Architecture](docs/01-architecture.md)
- [Environment setup](docs/02-environment-setup.md)
- [Implementation](docs/03-implementation.md)
- [Security controls](docs/04-security-controls.md)
- [Testing and validation](docs/05-testing-and-validation.md)
- [Troubleshooting](docs/06-troubleshooting.md)
- [Results and lessons](docs/07-results-and-lessons.md)

[Source](scripts/) · [Evidence](data/evidence/) · [Flows](docs/flows.md) · [Security checklist](docs/security-checklist.md) · [Primary references](docs/references.md).
