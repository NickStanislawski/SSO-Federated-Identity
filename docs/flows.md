# Protocol flows

## OIDC Authorization Code + PKCE

```mermaid
sequenceDiagram
 participant B as Browser
 participant RP as OIDC app
 participant I as Provider
 B->>RP: /login
 RP->>B: Redirect with state, nonce and S256 challenge
 B->>I: Authorization request
 Note over I: Local fixture automatically selects synthetic user
 I->>B: Redirect with one-time code and state
 B->>RP: /callback
 RP->>I: Code + verifier + client authentication
 I->>RP: Signed ID token and access token
 RP->>I: Trusted discovery/JWKS as needed
 RP->>RP: Validate token and map verified groups
 RP->>B: Opaque local session handle
 B->>RP: /protected
 RP->>RP: Enforce reader role and session expiry
```

## SAML SP-initiated sign-in

```mermaid
sequenceDiagram
 participant B as Browser
 participant SP as SAML app
 participant I as Provider
 B->>SP: /login
 SP->>SP: Store pending request ID and deadline
 SP->>B: HTTP Redirect with DEFLATE/base64 AuthnRequest
 B->>I: /saml/sso
 I->>B: Form containing signed Assertion in Response
 B->>SP: HTTP POST to ACS
 SP->>SP: Correlate request, pin certificate and verify signed element
 SP->>SP: Validate subject, issuer, audience, times and replay
 SP->>B: Local session; redirect to protected page
```
