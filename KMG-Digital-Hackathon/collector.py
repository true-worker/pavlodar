"""Local collector: authenticate completed buffer records, then archive."""
import os,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'src'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE','demodesk.config.settings')
from django.conf import settings
from portal.audit import read_event
def collect_once():
    count=0
    for path in (settings.RUNTIME/'journal'/'pending').glob('*.evt'):
        read_event(path)
        destination=settings.RUNTIME/'journal'/'received'/path.name
        destination.write_bytes(path.read_bytes())
        path.unlink()
        count+=1
    return count
if __name__=='__main__':
    if '--once' in sys.argv: print(collect_once())
    else:
        while True:
            collect_once()
            time.sleep(10)
