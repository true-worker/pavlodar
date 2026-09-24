"""Loopback reverse proxy and WSGI launcher. Ctrl+C stops all components."""
import os, sys, ssl, json, threading, subprocess, http.client
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE','demodesk.config.settings')
RUNTIME=Path(os.environ.get('HELPDESK_RUNTIME',ROOT/'runtime')).resolve()
config=json.loads((ROOT/'proxy.json').read_text())
for name in ['http_port','https_port','backend_port']:
    config[name]=int(os.environ.get('HELPDESK_'+name.upper(),config[name]))

class Proxy(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def transfer(self):
        secure=isinstance(self.connection,ssl.SSLSocket)
        if not secure and config['http_redirect']:
            self.send_response(308)
            self.send_header('Location',f'https://127.0.0.1:{config["https_port"]}{self.path}')
            self.send_header('Content-Length','0')
            self.send_header('Connection','close')
            self.end_headers()
            self.close_connection=True
            return
        try: length=int(self.headers.get('Content-Length','0'))
        except ValueError: self.send_error(400); return
        if length>2*1024*1024 or self.headers.get('Transfer-Encoding'):
            self.send_error(413); return
        body=self.rfile.read(length) if length else None
        hop={'connection','transfer-encoding','proxy-connection','x-forwarded-proto','x-forwarded-host','forwarded','x-forwarded-for','content-length'}
        headers={k:v for k,v in self.headers.items() if k.lower() not in hop}
        headers['X-Forwarded-Proto']='https' if secure else 'http'
        headers['Connection']='close'
        backend=http.client.HTTPConnection('127.0.0.1',config['backend_port'],timeout=30)
        try:
            backend.request(self.command,self.path,body,headers)
            response=backend.getresponse()
            data=response.read()
            self.send_response(response.status)
            for key,value in response.getheaders():
                if key.lower() not in ('connection','transfer-encoding','content-length','server','date'): self.send_header(key,value)
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            if self.command!='HEAD': self.wfile.write(data)
        finally: backend.close()
    do_GET=do_POST=do_HEAD=do_PUT=do_PATCH=do_DELETE=transfer

def main():
    from demodesk.config.wsgi import application
    from waitress import create_server
    from django.conf import settings
    settings.SECURE_SSL_HOST=f'127.0.0.1:{config["https_port"]}'
    backend=create_server(application,host='127.0.0.1',port=config['backend_port'],threads=4,trusted_proxy='127.0.0.1',trusted_proxy_headers={'x-forwarded-proto'},clear_untrusted_proxy_headers=True)
    http=ThreadingHTTPServer(('127.0.0.1',config['http_port']),Proxy)
    https=ThreadingHTTPServer(('127.0.0.1',config['https_port']),Proxy)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=getattr(ssl.TLSVersion,config['minimum_tls'])
    context.set_ciphers(config['ciphers'])
    context.load_cert_chain(RUNTIME/'keys'/'server.pem',RUNTIME/'keys'/'server.key')
    https.socket=context.wrap_socket(https.socket,server_side=True)
    collector=subprocess.Popen([sys.executable,str(ROOT/'collector.py')],cwd=ROOT,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    for target in [backend.run,http.serve_forever,https.serve_forever]: threading.Thread(target=target,daemon=True).start()
    print(f'Helpdesk: https://127.0.0.1:{config["https_port"]} | http://127.0.0.1:{config["http_port"]}',flush=True)
    try: threading.Event().wait()
    except KeyboardInterrupt: pass
    finally:
        collector.terminate();collector.wait(timeout=10)
        http.shutdown();https.shutdown();backend.close()
if __name__=='__main__': main()
