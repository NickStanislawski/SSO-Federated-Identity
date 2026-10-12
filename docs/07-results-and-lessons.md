# Results and lessons

## Verified outcomes

Separate local OIDC and SAML apps completed sign-in using real RSA signatures. Authorization Code + PKCE, group role mapping, invalid artifact rejection, replay prevention, local logout and session expiry were exercised. All 37 tests and 7 configuration checks passed. Source, dependency versions, sanitized response events and evidence are preserved.

## V1 and V2 boundaries

V1: local federation foundation implemented/validated; Okta provider setup and commercial tenant evidence pending. V2: configuration checks, negative tests, response-event summarization and local session control implemented/validated. Real MFA, conditional access, IdP/app correlation, certificate rollover execution and global session termination remain pending.

## Lessons

Use maintained libraries for cryptographic verification; consume only the verified assertion; preserve request correlation; keep authorization separate from sign-in; understand canonicalization and front-channel bindings; separate HTTP response metrics from authentication metrics; do not claim a context check proves MFA enrollment.

## Next steps and portfolio claims

PROJECT-STATUS.md tracks the original nine criteria. Seven are demonstrated in the local scope; real MFA and complete screenshot/tenant evidence are pending. Public GitHub publication has not occurred. Safe portfolio wording: “Built and tested separate local OIDC and SAML federation apps with 37 automated security scenarios and structured configuration checks.” Do not claim Okta deployment, production SSO, MFA enforcement or enterprise operational experience until validated.

