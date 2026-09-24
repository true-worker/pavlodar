"""Initialize a local, synthetic Helpdesk installation."""
import os, secrets, sys, subprocess, ipaddress
from pathlib import Path
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
ROOT=Path(__file__).resolve().parent
RUNTIME=Path(os.environ.get('HELPDESK_RUNTIME',ROOT/'runtime')).resolve()
for folder in ['keys','media','journal/pending','journal/received','static']:
    (RUNTIME/folder).mkdir(parents=True,exist_ok=True)
for filename,size in [('data.key',64),('journal.key',32)]:
    path=RUNTIME/('journal' if filename=='journal.key' else 'keys')/filename
    if not path.exists(): path.write_bytes(secrets.token_bytes(size))
path=RUNTIME/'keys'/'django.key'
if not path.exists(): path.write_text(secrets.token_urlsafe(64))
if not (RUNTIME/'keys'/'server.pem').exists():
    key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc)-timedelta(minutes=1)).not_valid_after(datetime.now(timezone.utc)+timedelta(days=30)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).sign(key,hashes.SHA256()))
    (RUNTIME/'keys'/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (RUNTIME/'keys'/'server.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
from portal.local_acl import configure
configure(RUNTIME)
if '--keys-only' not in sys.argv:
    for args in [('migrate','--noinput'),('seed_demo',),('collectstatic','--noinput'),('check',)]:
        subprocess.run([sys.executable,str(ROOT/'manage.py'),*args],cwd=ROOT,check=True)
print('Local runtime initialized:',RUNTIME)
