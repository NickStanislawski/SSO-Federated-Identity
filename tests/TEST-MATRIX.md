# Executed test matrix

Final actual result: all 37 scenarios passed; see results.txt. Negative cases expect rejection and positive cases expect the asserted result.

| Suite | Scenario | Expected | Actual |
|---|---|---|---|
| TokenTests | test_valid_signature_claims | Pass the assertions in canonical test method | PASS |
| TokenTests | test_expired | Pass the assertions in canonical test method | PASS |
| TokenTests | test_issuer | Pass the assertions in canonical test method | PASS |
| TokenTests | test_audience | Pass the assertions in canonical test method | PASS |
| TokenTests | test_nonce | Pass the assertions in canonical test method | PASS |
| TokenTests | test_missing_groups | Pass the assertions in canonical test method | PASS |
| TokenTests | test_malformed | Pass the assertions in canonical test method | PASS |
| TokenTests | test_tampered_signature | Pass the assertions in canonical test method | PASS |
| TokenTests | test_mfa_context | Pass the assertions in canonical test method | PASS |
| TokenTests | test_unknown_group | Pass the assertions in canonical test method | PASS |
| TokenTests | test_group_type | Pass the assertions in canonical test method | PASS |
| SamlTests | test_valid_signed_assertion | Pass the assertions in canonical test method | PASS |
| SamlTests | test_tampered_assertion | Pass the assertions in canonical test method | PASS |
| SamlTests | test_wrong_certificate | Pass the assertions in canonical test method | PASS |
| SamlTests | test_wrong_issuer | Pass the assertions in canonical test method | PASS |
| SamlTests | test_wrong_audience | Pass the assertions in canonical test method | PASS |
| SamlTests | test_expired_assertion | Pass the assertions in canonical test method | PASS |
| SamlTests | test_wrong_recipient | Pass the assertions in canonical test method | PASS |
| SamlTests | test_wrong_request | Pass the assertions in canonical test method | PASS |
| SamlTests | test_missing_attributes | Pass the assertions in canonical test method | PASS |
| SamlTests | test_replay | Pass the assertions in canonical test method | PASS |
| SamlTests | test_duplicate_assertion | Pass the assertions in canonical test method | PASS |
| SamlTests | test_entity_input | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_oidc_code_pkce_roundtrip | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_oidc_invalid_state | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_redirect_mismatch | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_pkce_and_code_replay | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_saml_separate_app_roundtrip | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_unauthenticated_denied | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_logout_and_session_expiry | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_role_denial | Pass the assertions in canonical test method | PASS |
| IntegrationTests | test_mfa_application_denial | Pass the assertions in canonical test method | PASS |
| AutomationTests | test_valid_config | Pass the assertions in canonical test method | PASS |
| AutomationTests | test_unsafe_redirect | Pass the assertions in canonical test method | PASS |
| AutomationTests | test_near_expiry | Pass the assertions in canonical test method | PASS |
| AutomationTests | test_binding_mismatch | Pass the assertions in canonical test method | PASS |
| AutomationTests | test_report_categories | Pass the assertions in canonical test method | PASS |

Canonical test bodies specify precise codes/exceptions/roles. This matrix is derived from the executed suite, not additional tests.
