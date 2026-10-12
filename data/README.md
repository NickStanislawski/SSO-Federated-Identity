# Synthetic configuration and evidence

config.json declares local configuration checked by audit.py; it does not automatically configure apps or a remote provider. Canonical app policy constants are in scripts/apps.py and security.py. Config checks detect declaration consistency, not tenant state. Evidence has sanitized route/status/category records; no token, assertion, key or real identity values are retained. lab-cert.pem is public fixture signing material and contains no private key.

After tests generate events.json and lab-cert.pem, run audit.py with a new output name. Keep real exports in ignored data/live/ and sanitize before sharing.
