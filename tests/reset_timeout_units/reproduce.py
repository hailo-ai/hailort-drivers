"""Compile selected real driver methods against software-only kernel doubles."""
import argparse,json,subprocess,hashlib
from pathlib import Path
from extractor import function
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',required=True,type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
here=Path(__file__).resolve().parent;source=a.source_root/'linux/pcie/src/pcie.c';text=source.read_text();kind='timeout';rows=[];commands=[]
def run(argv,label):
 r=subprocess.run(list(map(str,argv)),capture_output=True,timeout=30);(out/(label+'.stdout')).write_bytes(r.stdout);(out/(label+'.stderr')).write_bytes(r.stderr);commands.append({'argv':list(map(str,argv)),'returncode':r.returncode});(out/'commands.json').write_text(json.dumps(commands,indent=2));return r
if kind=='error':
 (out/'selected.inc').write_text(function(text,'load_nnc_firmware'))
 c=out/'fixture.c';c.write_bytes((here/'fixture.c').read_bytes());exe=out/'fixture'
 r=run(['gcc','-std=gnu11','-g','-O1','-Wall','-Wextra','-Werror','-Wno-unused-but-set-variable','-fsanitize=address,undefined','-fno-sanitize-recover=all','-I'+str(out),c,'-o',exe],'compile');assert r.returncode==0,r.stderr.decode()
 cases=[(0,1,1,0,1),(-5,1,1,0,1),(-19,1,1,0,1),(-110,1,1,0,1),(-512,1,1,0,1),(0,1,0,0,1),(0,0,1,0,1),(0,0,1,-5,1),(0,0,1,0,0)]
 for i,case in enumerate(cases):
  r=run([exe,*map(str,case)],'case-'+str(i));assert r.returncode==0,r.stderr.decode();ret,resets,batches,waits,inits=map(int,r.stdout.split())
  error,present,support,batch,ack=case;reset=present and support;stops=reset and error<0;skip=present and not support
  expected=error if stops else 0 if skip else batch if batch<0 else 0 if ack else -110
  correct=(ret,resets,batches,waits,inits)==(expected,int(reset),int(not(stops or skip)),int(not(stops or skip) and batch==0),int(not(stops or skip)))
  rows.append({'input':case,'ret':ret,'resets':resets,'batches':batches,'waits':waits,'inits':inits,'pass':correct})
else:
 (out/'wait.inc').write_text(function(text,'wait_for_firmware_completion'));(out/'selected.inc').write_text(function(text,'hailo_pcie_soft_reset'))
 c=out/'fixture.c';c.write_bytes((here/'fixture.c').read_bytes())
 for hz in [100,250,300,1000,1024]:
  for ms in [5000,5000000]:
   key=f'{hz}-{ms}';exe=out/('fixture-'+key)
   r=run(['gcc','-std=gnu11','-g','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',f'-DHZ={hz}',f'-DFIRMWARE_WAIT_TIMEOUT_MS={ms}','-I'+str(out),c,'-o',exe],'compile-'+key);assert r.returncode==0,r.stderr.decode()
   r=run([exe],'run-'+key);assert r.returncode==0,r.stderr.decode();ret,conversions,ticks=map(int,r.stdout.split());rows.append({'hz':hz,'ms':ms,'return':ret,'conversions':conversions,'ticks':ticks,'pass':ret==0 and conversions==1 and ticks==(ms*hz+999)//1000})
result={'scope':'source-subset simulation, no hardware','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'total':len(rows),'passed':sum(x['pass'] for x in rows),'cases':rows};(out/'results.json').write_text(json.dumps(result,indent=2));print(json.dumps(result));raise SystemExit(0 if result['passed']==result['total'] else 1)
