import base64,copy,json,logging,sys,threading,time,unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import jwt,requests
from cryptography.hazmat.primitives import serialization
from lxml import etree
from werkzeug.serving import make_server
from local_idp import keys,assertion,create_idp
from security import validate_id_token,validate_saml,roles,checks,challenge,NS
from apps import create_oidc,create_saml
from audit import report

logging.getLogger('werkzeug').setLevel(logging.ERROR)
ROOT=Path(__file__).resolve().parents[1]
class TokenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.key,cls.cert=keys();cls.pub=serialization.load_pem_private_key(cls.key,None).public_key()
    def setUp(self):self.c=dict(iss='https://idp.example.test',aud='client',sub='synthetic',iat=int(time.time()),exp=int(time.time())+300,nonce='nonce',groups=['employees'],amr=['mfa'])
    def validate(self):return validate_id_token(jwt.encode(self.c,self.key,algorithm='RS256'),self.pub,'https://idp.example.test','client','nonce')
    def test_valid_signature_claims(self):self.assertEqual(self.validate()['roles'],['reader'])
    def test_expired(self):self.c['exp']=int(time.time())-1;self.assertRaises(jwt.ExpiredSignatureError,self.validate)
    def test_issuer(self):self.c['iss']='https://wrong.test';self.assertRaises(jwt.InvalidIssuerError,self.validate)
    def test_audience(self):self.c['aud']='other';self.assertRaises(jwt.InvalidAudienceError,self.validate)
    def test_nonce(self):self.c['nonce']='wrong';self.assertRaises(ValueError,self.validate)
    def test_missing_groups(self):del self.c['groups'];self.assertRaises(jwt.MissingRequiredClaimError,self.validate)
    def test_malformed(self):self.assertRaises(jwt.DecodeError,validate_id_token,'bad',self.pub,'i','a','n')
    def test_tampered_signature(self):
        token=jwt.encode(self.c,self.key,algorithm='RS256');h,p,s=token.split('.');c=copy.copy(self.c);c['groups']=['admins'];p=base64.urlsafe_b64encode(json.dumps(c).encode()).decode().rstrip('=')
        self.assertRaises(jwt.InvalidSignatureError,validate_id_token,'.'.join([h,p,s]),self.pub,'https://idp.example.test','client','nonce')
    def test_mfa_context(self):
        self.c['amr']=['pwd'];self.assertRaises(ValueError,validate_id_token,jwt.encode(self.c,self.key,algorithm='RS256'),self.pub,'https://idp.example.test','client','nonce',True)
    def test_unknown_group(self):self.assertEqual(roles(['unknown']),[])
    def test_group_type(self):self.assertRaises(ValueError,roles,'admins')

class SamlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.key,cls.cert=keys()
    def setUp(self):self.used=set()
    def xml(self,changes=None):return assertion(self.key,self.cert,'https://idp.test','urn:lab:sp','https://sp.test/acs','_request',changes)
    def validate(self,xml):return validate_saml(xml,self.cert,'https://idp.test','urn:lab:sp','https://sp.test/acs','_request',self.used)
    def test_valid_signed_assertion(self):self.assertEqual(self.validate(self.xml())['roles'],['finance','reader'])
    def test_tampered_assertion(self):self.assertRaises(Exception,self.validate,self.xml().replace(b'synthetic-user',b'intruder-user'))
    def test_wrong_certificate(self):
        _,cert=keys();self.assertRaises(Exception,validate_saml,self.xml(),cert,'https://idp.test','urn:lab:sp','https://sp.test/acs','_request',set())
    def test_wrong_issuer(self):self.assertRaises(ValueError,self.validate,self.xml({'issuer':'wrong'}))
    def test_wrong_audience(self):self.assertRaises(ValueError,self.validate,self.xml({'audience':'wrong'}))
    def test_expired_assertion(self):self.assertRaises(ValueError,self.validate,self.xml({'after':datetime.now(timezone.utc)-timedelta(seconds=1)}))
    def test_wrong_recipient(self):self.assertRaises(ValueError,self.validate,self.xml({'recipient':'wrong'}))
    def test_wrong_request(self):self.assertRaises(ValueError,self.validate,self.xml({'rid':'wrong'}))
    def test_missing_attributes(self):self.assertRaises(ValueError,self.validate,self.xml({'groups':[]}))
    def test_replay(self):x=self.xml();self.validate(x);self.assertRaises(ValueError,self.validate,x)
    def test_duplicate_assertion(self):
        r=etree.fromstring(self.xml());r.append(copy.deepcopy(r.find('s:Assertion',NS)));self.assertRaises(ValueError,self.validate,etree.tostring(r))
    def test_entity_input(self):self.assertRaises(ValueError,self.validate,b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///private">]><x/>')

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.idp=create_idp();cls.oidc=create_oidc('http://127.0.0.1:8000','lab-client','synthetic-secret','http://127.0.0.1:8001/callback',lab=True)
        cls.saml=create_saml('http://127.0.0.1:8000',cls.idp.config['CERT'],'http://127.0.0.1:8002/acs','http://127.0.0.1:8000/saml/sso',lab=True)
        cls.servers=[make_server('127.0.0.1',p,a,threaded=True) for p,a in [(8000,cls.idp),(8001,cls.oidc),(8002,cls.saml)]]
        for s in cls.servers:threading.Thread(target=s.serve_forever,daemon=True).start()
    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:s.shutdown();s.server_close()
        evidence=ROOT/'data/evidence';evidence.mkdir(parents=True,exist_ok=True)
        events=cls.oidc.config['EVENTS']+cls.saml.config['EVENTS'];(evidence/'events.json').write_text(json.dumps(events,indent=2));(evidence/'monitoring-report.json').write_text(json.dumps(report(events),indent=2));(evidence/'lab-cert.pem').write_bytes(cls.idp.config['CERT'])
    def test_oidc_code_pkce_roundtrip(self):
        with requests.Session() as s:
            r=s.get('http://127.0.0.1:8001/login',timeout=5);self.assertEqual(r.status_code,200);self.assertEqual(r.json()['roles'],['finance','reader'])
    def test_oidc_invalid_state(self):
        r=requests.get('http://127.0.0.1:8001/callback?code=bad&state=bad',timeout=5);self.assertEqual(r.status_code,400)
    def test_redirect_mismatch(self):
        r=requests.get('http://127.0.0.1:8000/authorize',params={'redirect_uri':'https://attacker.test'},timeout=5);self.assertEqual(r.status_code,400)
    def test_pkce_and_code_replay(self):
        q=dict(client_id='lab-client',redirect_uri='http://127.0.0.1:8001/callback',response_type='code',scope='openid',state='test',nonce='test',code_challenge=challenge('verifier'),code_challenge_method='S256')
        r=requests.get('http://127.0.0.1:8000/authorize',params=q,allow_redirects=False,timeout=5)
        from urllib.parse import urlparse,parse_qs
        code=parse_qs(urlparse(r.headers['Location']).query)['code'][0];data=dict(code=code,grant_type='authorization_code',redirect_uri=q['redirect_uri'],code_verifier='wrong')
        self.assertEqual(requests.post('http://127.0.0.1:8000/token',data=data,auth=('lab-client','synthetic-secret'),timeout=5).status_code,400)
        data['code_verifier']='verifier';self.assertEqual(requests.post('http://127.0.0.1:8000/token',data=data,auth=('lab-client','synthetic-secret'),timeout=5).status_code,400)
    def test_saml_separate_app_roundtrip(self):
        with requests.Session() as s:
            r=s.get('http://127.0.0.1:8002/login',timeout=5);html=etree.HTML(r.text);value=html.xpath('//input[@name="SAMLResponse"]/@value')[0]
            r=s.post('http://127.0.0.1:8002/acs',data={'SAMLResponse':value},timeout=5);self.assertEqual(r.status_code,200);self.assertIn('reader',r.json()['roles'])
    def test_unauthenticated_denied(self):self.assertEqual(requests.get('http://127.0.0.1:8001/protected',timeout=5).status_code,401)
    def test_logout_and_session_expiry(self):
        with requests.Session() as s:
            r=s.get('http://127.0.0.1:8001/login',timeout=5);csrf=r.json()['csrf']
            self.assertEqual(s.post('http://127.0.0.1:8001/logout',data={'csrf':'wrong'},timeout=5).status_code,403)
            s.post('http://127.0.0.1:8001/logout',data={'csrf':csrf},timeout=5);self.assertEqual(s.get('http://127.0.0.1:8001/protected',timeout=5).status_code,401)
            s.get('http://127.0.0.1:8001/login',timeout=5)
            for row in self.oidc.config['SESSIONS'].values():row['exp']=time.time()-1
            self.assertEqual(s.get('http://127.0.0.1:8001/protected',timeout=5).status_code,401)
    def test_role_denial(self):
        c=self.oidc.test_client()
        with c.session_transaction() as s:s['sid']='denial'
        self.oidc.config['SESSIONS']['denial']=dict(sub='synthetic',roles=[],exp=time.time()+60,csrf='x')
        self.assertEqual(c.get('/protected').status_code,403)
    def test_mfa_application_denial(self):
        app=create_oidc('http://127.0.0.1:8000','lab-client','synthetic-secret','http://127.0.0.1:8001/callback',lab=True,require_mfa=True)
        original=self.servers[1].app;self.servers[1].app=app
        try:self.assertEqual(requests.get('http://127.0.0.1:8001/login',timeout=5).status_code,400)
        finally:self.servers[1].app=original

class AutomationTests(unittest.TestCase):
    def setUp(self):self.key,self.cert=keys();self.config=json.loads((ROOT/'data/config.json').read_text())
    def test_valid_config(self):self.assertTrue(all(c['pass'] for c in checks(self.config,self.cert)))
    def test_unsafe_redirect(self):
        self.config['redirect_uris']=['http://remote.test/callback','https://sp.test/*','https://sp.test/callback#fragment'];self.assertFalse(any(c['pass'] for c in checks(self.config,self.cert) if c['check']=='redirect_uri'))
    def test_near_expiry(self):self.assertFalse(next(c['pass'] for c in checks(self.config,self.cert,datetime.now(timezone.utc)+timedelta(days=80)) if c['check']=='certificate_lifetime'))
    def test_binding_mismatch(self):self.config['metadata_acs']='wrong';self.assertFalse(next(c['pass'] for c in checks(self.config,self.cert) if c['check']=='saml_binding'))
    def test_report_categories(self):self.assertEqual(report([dict(category='failure',application='oidc',path='/callback',status=400)])['categories'],{'failure':1})
if __name__=='__main__':unittest.main(verbosity=2)
