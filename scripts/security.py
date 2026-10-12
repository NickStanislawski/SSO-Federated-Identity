"""Restricted local federation profile; never a general SAML implementation."""
import base64, hashlib, hmac, json, time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import jwt
from cryptography import x509
from lxml import etree
from signxml import XMLVerifier, SignatureConfiguration, SignatureMethod, DigestAlgorithm

NS={'s':'urn:oasis:names:tc:SAML:2.0:assertion','p':'urn:oasis:names:tc:SAML:2.0:protocol'}
def challenge(verifier): return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
def roles(groups):
    if not isinstance(groups,list) or any(not isinstance(g,str) for g in groups): raise ValueError('Invalid groups')
    return sorted({{'employees':'reader','finance':'finance','admins':'admin'}[g] for g in groups if g in {'employees','finance','admins'}})
def validate_id_token(token, public_key, issuer, audience, nonce, require_mfa=False):
    c=jwt.decode(token,public_key,algorithms=['RS256'],issuer=issuer,audience=audience,options={'require':['iss','aud','exp','iat','sub','nonce','groups']})
    if not isinstance(c['sub'],str) or not c['sub']:raise ValueError('Invalid subject')
    if not isinstance(c['nonce'],str) or not hmac.compare_digest(c['nonce'],nonce):raise ValueError('Invalid nonce')
    if require_mfa and ('mfa' not in c.get('amr',[])):raise ValueError('MFA context required')
    c['roles']=roles(c['groups']);return c
def instant(value):
    d=datetime.fromisoformat(value.replace('Z','+00:00'))
    if d.tzinfo is None:raise ValueError('Timezone required')
    return d.timestamp()

def validate_saml(xml, cert, issuer, audience, recipient, request_id, used, now=None):
    now=time.time() if now is None else now
    if b'<!DOCTYPE' in xml.upper() or len(xml)>100000:raise ValueError('Unsafe XML')
    parser=etree.XMLParser(resolve_entities=False,no_network=True,load_dtd=False)
    response=etree.fromstring(xml,parser)
    if response.tag!='{'+NS['p']+'}Response' or response.get('Destination')!=recipient or response.get('InResponseTo')!=request_id:raise ValueError('Response binding')
    ids=response.xpath('//@ID')
    if len(ids)!=len(set(ids)):raise ValueError('Duplicate XML ID')
    assertions=response.findall('s:Assertion',NS)
    if len(assertions)!=1:raise ValueError('Exactly one assertion required')
    status=response.find('p:Status/p:StatusCode',NS)
    if status is None or status.get('Value')!=NS['p']+':Success':raise ValueError('SAML failure')
    trusted=x509.load_pem_x509_certificate(cert)
    if not trusted.not_valid_before_utc.timestamp()<=now<trusted.not_valid_after_utc.timestamp():raise ValueError('Certificate validity')
    result=XMLVerifier().verify(assertions[0],x509_cert=cert,expect_config=SignatureConfiguration(location='./',signature_methods=frozenset({SignatureMethod.RSA_SHA256}),digest_algorithms=frozenset({DigestAlgorithm.SHA256})))
    a=result.signed_xml
    if a.tag!='{'+NS['s']+'}Assertion' or a.get('ID')!=assertions[0].get('ID'):raise ValueError('Wrong signed element')
    if a.get('ID') in used:raise ValueError('Replay')
    if a.findtext('s:Issuer',namespaces=NS)!=issuer:raise ValueError('Issuer')
    c=a.find('s:Conditions',NS)
    if c is None or not instant(c.get('NotBefore'))<=now<instant(c.get('NotOnOrAfter')):raise ValueError('Assertion lifetime')
    restrictions=c.findall('s:AudienceRestriction',NS)
    if not restrictions or any(audience not in r.xpath('./s:Audience/text()',namespaces=NS) for r in restrictions):raise ValueError('Audience')
    confirmations=a.findall('s:Subject/s:SubjectConfirmation',NS)
    if len(confirmations)!=1 or confirmations[0].get('Method')!=NS['s']+':cm:bearer':raise ValueError('Confirmation')
    sc=confirmations[0].find('s:SubjectConfirmationData',NS)
    if sc is None or sc.get('Recipient')!=recipient or sc.get('InResponseTo')!=request_id or now>=instant(sc.get('NotOnOrAfter')):raise ValueError('Subject binding')
    subject=a.findtext('s:Subject/s:NameID',namespaces=NS)
    if not subject:raise ValueError('NameID')
    groups=a.xpath('./s:AttributeStatement/s:Attribute[@Name="groups"]/s:AttributeValue/text()',namespaces=NS)
    if not groups:raise ValueError('Missing groups')
    mapped=roles(groups);used.add(a.get('ID'));return {'sub':subject,'roles':mapped,'exp':instant(c.get('NotOnOrAfter'))}

def checks(config, cert, now=None):
    now=datetime.now(timezone.utc) if now is None else now
    results=[]
    for uri in config['redirect_uris']:
        u=urlparse(uri); ok=(u.scheme=='https' or config.get('lab') and u.scheme=='http' and u.hostname in {'localhost','127.0.0.1'}) and not u.fragment and not u.username and '*' not in uri
        results.append({'check':'redirect_uri','target':uri,'pass':bool(ok)})
    c=x509.load_pem_x509_certificate(cert)
    days=(c.not_valid_after_utc-now).days
    results.extend([{'check':'certificate_lifetime','pass':c.not_valid_before_utc<=now and days>=30,'days_remaining':days},{'check':'pkce','pass':config.get('pkce')=='S256'},{'check':'signing_algorithm','pass':config.get('algorithm')=='RS256'},{'check':'required_claims','pass':{'sub','groups','nonce'}<=set(config.get('required_claims',[]))},{'check':'saml_binding','pass':config.get('acs')==config.get('metadata_acs') and bool(config.get('entity_id'))},{'check':'role_mapping','pass':config.get('role_mapping')=={'employees':'reader','finance':'finance','admins':'admin'}}])
    return results
