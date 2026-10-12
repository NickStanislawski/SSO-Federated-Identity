# Testing and validation

## Objective and methodology

Run 37 unittest scenarios with ephemeral RSA material and a pinned synthetic certificate. Integration tests start three separate localhost HTTP services, exercise Authlib discovery and JWKS loading, exchange an authorization code with PKCE, and submit a signed SAML assertion to a separate ACS. Requests follows redirects and maintains browser-like cookies; this is an HTTP integration test, not a browser UI test.

## Expected and observed

Expected: 37 passes, trusted OIDC/SAML sign-in accepted, malformed or untrusted artifacts rejected, local logout and expiry deny access, declared configuration checks pass. Observed: 37 tests passed; 7 configuration checks passed; 20 recorded app events (14 HTTP successes, 5 access denials, 1 failure) in the final run. Tests for alternate MFA app instances are validated but are not included in the main app event export.

Tests/results.txt is the raw final unittest log. data/evidence/security-report.json contains measured automation results. data/evidence/events.json records app responses without credentials. Public certificate is evidence of fixture trust only; its 90-day lifetime starts at test execution. No private key is retained. Its expiry check eventually fails as expected; rerun tests to generate a fresh fixture certificate.

## Test matrix and evidence

tests/TEST-MATRIX.md maps every test method to its expected result and actual pass status. Direct token tests validate PyJWT rather than Authlib, while the actual client round-trip tests exercise Authlib. Direct assertion negatives target the ACS's canonical verifier. MFA-context denial does not validate an enrolled factor. Tenant evidence and browser screenshots are pending.

## Reruns and recovery

Stop the interactive lab, preserve existing test/evidence files, run the suite, then write a new audit report name. Tests replace events.json and lab-cert.pem. Never combine a stale report and a fresh certificate as though they belong to one run. Compare the archive manifest for original artifact integrity; it is unsigned, so it is not tamper-proof evidence.

