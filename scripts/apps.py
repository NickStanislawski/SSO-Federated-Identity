import base64,os,secrets,time,zlib
from datetime import timedelta,datetime,timezone
from pathlib import Path
from urllib.parse import urlencode
from flask import Flask,session,redirect,request,jsonify
from authlib.integrations.flask_client import OAuth
from lxml import etree
from security import validate_saml,roles,NS

def base(name,secure=True):
    app=Flask(name);app.secret_key=secrets.token_hex(32);sessions={};app.config.update(SESSION_COOKIE_NAME=name,SESSION_COOKIE_SECURE=secure,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),MAX_CONTENT_LENGTH=150000,EVENTS=[])
    @app.after_request
    def audit(response):
        category='success' if response.status_code<400 else 'access_denial' if response.status_code in [401,403] else 'failure'
        app.config['EVENTS'].append({'timestamp':datetime.now(timezone.utc).isoformat(),'application':name,'path':request.path,'status':response.status_code,'category':category})
        response.headers['Cache-Control']='no-store';response.headers['X-Content-Type-Options']='nosniff';response.headers['Content-Security-Policy']="default-src 'self'; frame-ancestors 'none'"
        return response
    def identity():
        sid=session.get('sid');row=sessions.get(sid)
        if not row or row['exp']<=time.time():sessions.pop(sid,None);return None
        return row
    @app.get('/')
    def home():return '<h1>Federation lab</h1><a href="/login">Sign in</a> · <a href="/protected">Protected page</a>'
    @app.get('/protected')
    def protected():
        user=identity()
        if not user:return 'Authentication required',401
        if 'reader' not in user['roles']:return 'Access denied',403
        return jsonify(subject=user['sub'],roles=user['roles'],csrf=user['csrf'])
    @app.post('/logout')
    def logout():
        user=identity()
        if not user or not secrets.compare_digest(request.form.get('csrf',''),user['csrf']):return 'Invalid CSRF token',403
        sessions.pop(session.get('sid'),None);session.clear();return redirect('/')
    def sign_in(user):
        sessions.pop(session.get('sid'),None);session.clear();sid=secrets.token_urlsafe(32);session['sid']=sid;session.permanent=True
        sessions[sid]=dict(sub=user['sub'],roles=user['roles'],exp=min(user['exp'],time.time()+600),csrf=secrets.token_urlsafe(32))
    app.config['SESSIONS']=sessions;return app,sign_in

def create_oidc(issuer,client_id,client_secret,callback,lab=False,require_mfa=False):
    if not lab and (not issuer.startswith('https://') or not callback.startswith('https://')):raise ValueError('HTTPS required')
    app,sign_in=base('oidc_sp',secure=not lab)
    oauth=OAuth(app);client=oauth.register('idp',client_id=client_id,client_secret=client_secret,server_metadata_url=issuer.rstrip('/')+'/.well-known/openid-configuration',client_kwargs={'scope':'openid profile email','code_challenge_method':'S256'},claims_options={'iss':{'essential':True,'value':issuer}})
    @app.get('/login')
    def login():return client.authorize_redirect(callback,nonce=secrets.token_urlsafe(32))
    @app.get('/callback')
    def callback_route():
        try:
            token=client.authorize_access_token();u=dict(token['userinfo'])
            if not u.get('sub') or u.get('iss')!=issuer or not isinstance(u.get('groups'),list) or u.get('exp',0)<=time.time():raise ValueError('Claims')
            if require_mfa and 'mfa' not in u.get('amr',[]):raise ValueError('MFA context')
            u['roles']=roles(u['groups']);sign_in(u);return redirect('/protected')
        except Exception:
            session.clear();return 'Federation validation failed',400
    return app

def create_saml(issuer,cert,acs,sso,lab=False):
    if not lab and (not acs.startswith('https://') or not sso.startswith('https://')):raise ValueError('HTTPS required')
    app,sign_in=base('saml_sp',secure=not lab);pending={};used=set()
    # Cross-site SAML POST needs SameSite=None with Secure for HTTPS deployments.
    if not lab:app.config['SESSION_COOKIE_SAMESITE']='None'
    @app.get('/login')
    def login():
        rid='_'+secrets.token_hex(16);handle=secrets.token_urlsafe(32);session['pending']=handle;pending[handle]=(rid,time.time()+120)
        r=etree.Element('{'+NS['p']+'}AuthnRequest',nsmap={'samlp':NS['p'],'saml':NS['s']},ID=rid,Version='2.0',IssueInstant=datetime.now(timezone.utc).isoformat(),AssertionConsumerServiceURL=acs,Destination=sso,ProtocolBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')
        etree.SubElement(r,'{'+NS['s']+'}Issuer').text='urn:lab:sp'
        compressor=zlib.compressobj(wbits=-15);raw=compressor.compress(etree.tostring(r))+compressor.flush()
        return redirect(sso+'?'+urlencode({'SAMLRequest':base64.b64encode(raw).decode()}))
    @app.get('/metadata')
    def metadata():
        md='urn:oasis:names:tc:SAML:2.0:metadata';root=etree.Element('{'+md+'}EntityDescriptor',nsmap={'md':md},entityID='urn:lab:sp')
        descriptor=etree.SubElement(root,'{'+md+'}SPSSODescriptor',protocolSupportEnumeration=NS['p'],AuthnRequestsSigned='false',WantAssertionsSigned='true')
        etree.SubElement(descriptor,'{'+md+'}AssertionConsumerService',Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',Location=acs,index='0',isDefault='true')
        return app.response_class(etree.tostring(root),mimetype='application/samlmetadata+xml')
    @app.post('/acs')
    def consume():
        try:
            rid,deadline=pending.pop(session.pop('pending',None))
            if deadline<=time.time():raise ValueError('Request expired')
            xml=base64.b64decode(request.form['SAMLResponse'],validate=True)
            u=validate_saml(xml,cert,issuer,'urn:lab:sp',acs,rid,used);sign_in(u);return redirect('/protected')
        except Exception:session.clear();return 'SAML validation failed',400
    return app
