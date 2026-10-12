# Implementation

## Objective

Provide reproducible OIDC and SAML sign-in flows, least-privilege group mapping, security automation, and inspectable evidence.

## OIDC app

apps.py:create_oidc() registers the configured issuer's discovery URL with Authlib and requests openid/profile/email scopes plus S256 PKCE. /login generates a nonce; Authlib keeps state and verifier correlation. /callback calls authorize_access_token(), which exchanges the code and validates the ID token through discovery/JWKS. Explicit checks enforce the configured issuer, nonempty subject, groups array, expiry, and optional MFA context before establishing a server-side session. Access and ID tokens are not persisted in cookies or audit files.

## SAML app

create_saml() generates an AuthnRequest with unique ID, destination, entity ID and ACS. The HTTP Redirect request uses raw DEFLATE, base64 and URL encoding; the provider returns a signed assertion through HTTP POST. A pending handle in the browser cookie binds the response to the request and expires after 120 seconds. The ACS uses a pinned certificate and checks destination, request correlation, success status, single assertion, duplicate IDs, signature, issuer, audience, validity interval, NameID, bearer confirmation, recipient, groups and replay. It consumes only SignXML's verified signed_xml. /metadata exposes the SP entity ID and POST ACS.

The custom profile accepts one signed unencrypted assertion, SP-initiated login and a single bearer confirmation. It does not support encrypted assertions, IdP-initiated SSO, signed requests, multiple confirmation alternatives, or SAML Single Logout. Use a maintained full SAML toolkit for production interoperability.

## Authorization and sessions

employees → reader, finance → finance, admins → admin. Unknown groups map to no role; groups must be a list. /protected requires reader, so finance/admin alone does not grant access. Identity sessions expire at the earlier of token/assertion expiry and ten minutes. A server-side record makes logout revoke the local session even if a cookie is replayed. Logout is POST with CSRF validation. IdP-global logout is not implemented.

## Automation

security.py:checks() evaluates redirect safety, certificate lifetime, S256 PKCE declaration, signing algorithm declaration, required-claim declaration, ACS string consistency and role mapping. These are configuration checks; they do not inspect a remote tenant or parse IdP metadata. audit.py summarizes sanitized app events by outcome/status and provides generic troubleshooting hints. HTTP successes include redirects and are not a count of completed authentications. Cross-provider correlation remains pending.

## Validation, evidence and troubleshooting

37 tests exercise the flows and controls. Evidence is in data/evidence/ and tests/results.txt. Failure callbacks return a generic response and establish no session. See docs/06-troubleshooting.md for diagnosed build issues and failure analysis.

