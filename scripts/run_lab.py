"""Run three separate local apps. Synthetic sign-in only."""
import threading,logging
from werkzeug.serving import make_server
from local_idp import create_idp
from apps import create_oidc,create_saml

def main():
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    idp=create_idp();oidc=create_oidc('http://127.0.0.1:8000','lab-client','synthetic-secret','http://127.0.0.1:8001/callback',lab=True)
    saml=create_saml('http://127.0.0.1:8000',idp.config['CERT'],'http://127.0.0.1:8002/acs','http://127.0.0.1:8000/saml/sso',lab=True)
    servers=[make_server('127.0.0.1',port,app,threaded=True) for port,app in [(8000,idp),(8001,oidc),(8002,saml)]]
    for s in servers:threading.Thread(target=s.serve_forever,daemon=True).start()
    print('Synthetic lab: OIDC http://127.0.0.1:8001 | SAML http://127.0.0.1:8002. Enter to stop.')
    try:input()
    finally:
        for s in servers:s.shutdown();s.server_close()
if __name__=='__main__':main()
