# Okta integration runbook — Planned, not tenant validated

## Prerequisites and boundary

Use an authorized development tenant with the features required for OIDC, SAML and the selected assurance policy. The current provider guide lists an Integrator Free Plan org as a development prerequisite. Do not infer access to custom authorization-server policies or contextual controls from the plan name. This project has no tenant credentials and made no tenant changes.

## OIDC app registration

1. Create test users and groups employees, finance and admins; use fictional records and controlled assignments.
2. In the Admin Console, create an OIDC Web Application. Register the exact HTTPS callback at your reverse-proxied application, e.g. https://YOUR-APP-HOST/callback. Choose Authorization Code and confirm PKCE support with S256. This is a confidential server-side client; store the secret locally.
3. Select the issuer/authorization server supported by your tenant. Confirm its discovery issuer, authorize/token/JWKS endpoints, access policy and group-claim support. Configure groups in the ID token so the RP's verified groups list is present; requesting a scope alone does not create a claim. This app requests openid profile email; additional provider scopes require an explicit client configuration change.
4. Assign only intended groups. Export a sanitized summary of assignment and claim configuration, excluding client secrets.
5. Set OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI in local environment variables according to .env.example. Do not commit the populated values. Run `python scripts/run_okta_oidc.py` behind an HTTPS reverse proxy. The callback is configured explicitly, so do not derive it from untrusted forwarding headers.
6. Test successful sign-in, missing groups, unassigned user, role denial and mismatched callback. Record actual sanitized results. Do not mark the tenant integration complete from local test evidence.

## SAML trust

1. Configure an HTTPS SP and a maintained production SAML toolkit. The included custom local profile is an educational reference and has not been tested against Okta.
2. In the tenant, create a SAML 2.0 app with your exact ACS and entity ID. NameID should be a stable synthetic subject. Map groups to the groups attribute.
3. Require signed assertions, RSA-SHA256 and SHA-256 digests; import the authoritative IdP metadata/certificate through a trusted administrative process. Do not trust a certificate merely because it appears in a response.
4. Exchange SP metadata, verify entity ID/ACS/certificates and configure the provider-specific issuer. Test SP-initiated login and signed assertion validation with the chosen toolkit. Record tampering, wrong audience, expired assertion, replay and unauthorized group failures.
5. The local /metadata endpoint and scripts/apps.py illustrate ACS and request binding. Adapting it to a tenant needs interoperability/security review, externalized configuration and persistent replay/session storage; it is not presented as a ready production connector.

## MFA and contextual access

1. Create an application authentication policy supported by the tenant. Enroll the representative test user in an allowed authenticator and require the intended assurance/factor combination for this app.
2. Test a fresh session, an unenrolled user, a valid challenge, challenge denial and access after satisfaction. Capture sanitized provider/app evidence without OTPs or recovery codes.
3. Validate the actual assurance claims returned by your issuer. REQUIRE_MFA=true currently checks for mfa in amr; adapt only after documenting the provider's supported semantics. A token label is not independent proof of a factor challenge.
4. If available, configure contextual rules using actual supported conditions; run matching/nonmatching cases and record results. Otherwise label the step Blocked or Not Applicable with rationale.

## Certificate rollover and logout

Inventory certificate/key identifiers and expiry. Introduce the new trusted verification key before switching signing, validate both keys during a bounded overlap, rotate signing, verify new tokens/assertions, wait for old artifact lifetimes to expire, then retire the old key. Roll back to the last valid signing/trust configuration if validation fails; retain sanitized change evidence. This drill has not been executed.

Local POST /logout terminates only the application session. Provider logout, token revocation, SAML SLO and termination across applications require separate provider-specific tests. Do not equate the local session test with global logout.
