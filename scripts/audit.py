import argparse,json
from collections import Counter
from pathlib import Path
from security import checks

def report(events):
    return {'events':len(events),'categories':dict(Counter(e['category'] for e in events)),'applications':dict(Counter(e['application'] for e in events)),'troubleshooting':[{'application':e['application'],'path':e['path'],'status':e['status'],'hint':'Inspect binding, signature and claims' if e['category']=='failure' else 'Inspect session and group mapping'} for e in events if e['category']!='success']}
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--cert',type=Path,required=True);p.add_argument('--events',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    if a.out.exists():raise ValueError('Choose a new evidence file')
    results=checks(json.loads(a.config.read_text()),a.cert.read_bytes());r=report(json.loads(a.events.read_text()));r['checks']=results;r['passed']=all(c['pass'] for c in results);a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2))
