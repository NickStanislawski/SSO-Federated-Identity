# Environment setup

## Objective and prerequisites

Python 3.12 was used for the recorded run. Install a compatible Python 3.11+ environment, access to package downloads, and free loopback ports 8000–8002. requirements.txt records tested package versions; these versions require a compatible platform and may need newer Python. Keep the project folder as the future repository root.

## Exact implementation


```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/run_lab.py
```

Open http://127.0.0.1:8001 for OIDC and http://127.0.0.1:8002 for SAML. The local IdP automatically selects a fictional user; it does not authenticate a person. SAML has a Continue button for the POST binding. Press Enter in the terminal to stop all three services. Bindings are loopback-only. Tests also need free ports 8000–8002; stop the interactive lab before testing.

Generate a fresh security report after tests:

```powershell
python scripts/audit.py --config data/config.json --cert data/evidence/lab-cert.pem --events data/evidence/events.json --out data/evidence/my-security-report.json
```

The report command rejects an existing output file. Tests overwrite their named test log/event snapshots when rerun; archive evidence before rerunning. Development dependencies were installed into an isolated workspace location during this build. They are not bundled in the deliverable; a normal rebuild uses the virtual environment above.

## Explanation and validation

The interactive launcher starts three threaded services and closes them on exit. The automated suite starts and shuts down its own services. Server-side sessions and replay caches are in memory, so restarting invalidates sessions. Restart also rotates the fixture signing key and certificate.

Expected: 37 tests pass, both application sign-ins reach /protected, unauthenticated access returns 401. Observed: all 37 tests passed in tests/results.txt. Package download and localhost execution initially encountered sandbox restrictions; authorized execution outside the restricted network context resolved them.

## Okta configuration boundary

Follow docs/okta-integration.md. Environment variables are read by run_okta_oidc.py; .env.example is a reference only and is not automatically loaded. No tenant login, app registration, MFA enrollment, or policy change occurred.

