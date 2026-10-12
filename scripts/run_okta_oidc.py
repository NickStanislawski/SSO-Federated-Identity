"""Okta adapter. Requires HTTPS reverse proxy; not tenant validated."""
import os
from apps import create_oidc
if __name__=='__main__':
    app=create_oidc(os.environ['OIDC_ISSUER'],os.environ['OIDC_CLIENT_ID'],os.environ['OIDC_CLIENT_SECRET'],os.environ['OIDC_REDIRECT_URI'],require_mfa=os.getenv('REQUIRE_MFA')=='true')
    app.run(host='127.0.0.1',port=8001,debug=False)
