"""Synthetic local-only IdP. Automatic fixture sign-in, not real authentication."""
import base64,json,secrets,time,zlib
from datetime import datetime,timedelta,timezone
from pathlib import Path
from urllib.parse import urlencode
import jwt
from flask import Flask,request,redirect,jsonify,Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner,methods
from security import NS,challenge

def keys():
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048);now=datetime.now(timezone.utc)
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Federation Lab')])
    cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=90)).sign(key,hashes.SHA256())
    return key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),cert.public_bytes(serialization.Encoding.PEM)
def assertion(key,cert,issuer,audience,recipient,rid,changes=None):
    now=datetime.now(timezone.utc); params={'issuer':issuer,'audience':audience,'recipient':recipient,'rid':rid,'sub':'synthetic-user','groups':['employees','finance'],'before':now-timedelta(seconds=10),'after':now+timedelta(minutes=5)};params.update(changes or {})
    a=etree.Element('{'+NS['s']+'}Assertion',nsmap={'saml':NS['s']},ID='_'+secrets.token_hex(16),Version='2.0',IssueInstant=now.isoformat())
    def child(parent,name,text=None,**attrs):
        node=etree.SubElement(parent,'{'+NS['s']+'}'+name,**attrs);node.text=text;return node
    child(a,'Issuer',params['issuer']);subject=child(a,'Subject');child(subject,'NameID',params['sub']);sc=child(subject,'SubjectConfirmation',Method=NS['s']+':cm:bearer');child(sc,'SubjectConfirmationData',Recipient=params['recipient'],InResponseTo=params['rid'],NotOnOrAfter=params['after'].isoformat())
    c=child(a,'Conditions',NotBefore=params['before'].isoformat(),NotOnOrAfter=params['after'].isoformat());ar=child(c,'AudienceRestriction');child(ar,'Audience',params['audience'])
    auth=child(a,'AuthnStatement',AuthnInstant=now.isoformat());context=child(auth,'AuthnContext');child(context,'AuthnContextClassRef',NS['s']+':ac:classes:PasswordProtectedTransport')
    attrs=child(a,'AttributeStatement');group=child(attrs,'Attribute',Name='groups')
    for g in params['groups']:child(group,'AttributeValue',g)
    signed=XMLSigner(method=methods.enveloped,signature_algorithm='rsa-sha256',digest_algorithm='sha256',c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#').sign(a,key=key,cert=cert,reference_uri=a.get('ID'))
    # SAML requires Signature after Issuer.
    sig=signed.find('{http://www.w3.org/2000/09/xmldsig#}Signature');signed.remove(sig);signed.insert(1,sig)
    response=etree.Element('{'+NS['p']+'}Response',nsmap={'samlp':NS['p']},ID='_'+secrets.token_hex(16),Version='2.0',IssueInstant=now.isoformat(),Destination=recipient,InResponseTo=rid)
    status=etree.SubElement(response,'{'+NS['p']+'}Status');etree.SubElement(status,'{'+NS['p']+'}StatusCode',Value=NS['p']+':Success');response.append(signed)
    return etree.tostring(response)

def create_idp(issuer='http://127.0.0.1:8000',callback='http://127.0.0.1:8001/callback',acs='http://127.0.0.1:8002/acs',material=None):
    app=Flask('local_idp');key,cert=material or keys();codes={}
    pub=serialization.load_pem_private_key(key,password=None).public_key();jwk=json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(pub));jwk.update(kid='lab-key',use='sig',alg='RS256')
    app.config.update(KEY=key,CERT=cert,CODES=codes,ISSUER=issuer)
    @app.get('/.well-known/openid-configuration')
    def discovery():return jsonify(issuer=issuer,authorization_endpoint=issuer+'/authorize',token_endpoint=issuer+'/token',jwks_uri=issuer+'/jwks',response_types_supported=['code'],subject_types_supported=['public'],id_token_signing_alg_values_supported=['RS256'],code_challenge_methods_supported=['S256'],token_endpoint_auth_methods_supported=['client_secret_basic'])
    @app.get('/jwks')
    def jwks():return jsonify(keys=[jwk])
    @app.get('/authorize')
    def authorize():
        q=request.args
        if q.get('redirect_uri')!=callback or q.get('client_id')!='lab-client' or q.get('response_type')!='code' or q.get('code_challenge_method')!='S256' or not all(q.get(k) for k in ['nonce','state','code_challenge']) or 'openid' not in q.get('scope','').split():return 'Invalid authorization request',400
        code=secrets.token_urlsafe(32);codes[code]=dict(q,issued=time.time());return redirect(callback+'?'+urlencode({'code':code,'state':q['state']}))
    @app.post('/token')
    def token():
        auth=request.authorization;q=request.form;record=codes.pop(q.get('code'),None)
        if not auth or auth.username!='lab-client' or auth.password!='synthetic-secret' or not record or q.get('grant_type')!='authorization_code' or q.get('redirect_uri')!=callback or time.time()-record['issued']>60 or challenge(q.get('code_verifier',''))!=record['code_challenge']:return jsonify(error='invalid_grant'),400
        now=int(time.time());claims=dict(iss=issuer,aud='lab-client',sub='synthetic-user',iat=now,exp=now+300,nonce=record['nonce'],groups=['employees','finance'],amr=['synthetic'])
        return jsonify(access_token=secrets.token_urlsafe(24),token_type='Bearer',expires_in=300,id_token=jwt.encode(claims,key,algorithm='RS256',headers={'kid':'lab-key'}))
    @app.get('/saml/sso')
    def saml():
        try:
            compressed=base64.b64decode(request.args['SAMLRequest'],validate=True);d=zlib.decompressobj(-15);raw=d.decompress(compressed,100001)
            if len(raw)>100000 or not d.eof or b'<!DOCTYPE' in raw.upper():raise ValueError()
            r=etree.fromstring(raw,etree.XMLParser(resolve_entities=False,no_network=True))
            if r.tag!='{'+NS['p']+'}AuthnRequest' or r.get('Destination')!=issuer+'/saml/sso' or r.get('ProtocolBinding')!='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' or r.get('AssertionConsumerServiceURL')!=acs or r.findtext('s:Issuer',namespaces=NS)!='urn:lab:sp' or not r.get('ID'):raise ValueError()
        except Exception:return 'Invalid request',400
        encoded=base64.b64encode(assertion(key,cert,issuer,'urn:lab:sp',acs,r.get('ID'))).decode()
        # Explicit submit button avoids requiring inline script.
        return Response(f'<form method="post" action="{acs}"><input type="hidden" name="SAMLResponse" value="{encoded}"><button>Continue synthetic SAML sign-in</button></form>',mimetype='text/html')
    return app
