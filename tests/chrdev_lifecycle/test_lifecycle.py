"""Source-derived chrdev lifecycle regression; no kernel or hardware calls.

The semaphore and kernel registration APIs are test doubles. A blocked-down
sentinel is a fixture observation, never a driver errno or a kernel execution.
"""
from pathlib import Path
import argparse,hashlib,json,os,re,resource,subprocess,tempfile
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
FUNCTIONS=['hailo_pcie_get_board_index','hailo_pcie_insert_board','hailo_pcie_remove_board','hailo_pcie_register_chrdev','hailo_pcie_unregister_chrdev','hailo_pcie_module_init','hailo_pcie_module_exit']
def function(text, name):
    match = re.search(r'(?m)^(?:static )?[^\n;]*\b' + name + r'\([^;]*?\)\s*\{', text)
    if not match:
        raise AssertionError('function not found: ' + name)
    # Tokenize comments/strings so braces in diagnostics cannot end a function.
    tokens = re.finditer(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',
                         text[match.end() - 1:], re.S)
    depth = 0
    for token in tokens:
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth:
                return text[match.start():match.end() - 1 + token.end()]
    raise AssertionError('unbalanced function: ' + name)

CASES={'class-fail': {'ret': -12, 'first': -12, 'class_null': 1, 'class_calls': 1, 'boards': 0},
 'class-fail-einval': {'ret': -22, 'class_null': 1, 'class_calls': 1, 'boards': 0},
 'failure-unwind': {'ret': -12, 'unregister': 1, 'destroy': 0, 'class_null': 1, 'major_owned': 0},
 'retry-success': {'first': -12, 'ret': 0, 'class_calls': 2, 'boards': 1},
 'retry-fail': {'first': -12, 'ret': -12, 'class_null': 1, 'class_calls': 2, 'boards': 0},
 'new-class-empty': {'ret': 0, 'class_calls': 1, 'boards': 1, 'indices': [0, 0, 0]},
 'existing-empty': {'ret': 0, 'class_calls': 0, 'boards': 1, 'indices': [0, 0, 0]},
 'existing-first-gap': {'ret': 0, 'class_calls': 0, 'boards': 2, 'indices': [0, 2, 0]},
 'existing-middle-gap': {'ret': 0, 'class_calls': 0, 'boards': 3, 'indices': [0, 1, 2]},
 'existing-tail': {'ret': 0, 'class_calls': 0, 'boards': 3, 'indices': [0, 1, 2]},
 'remove-null': {'ret': 0, 'boards': 0, 'down': 1, 'up': 1},
 'insert-remove': {'ret': 0, 'boards': 0, 'down': 2, 'up': 2},
 'unregister-no-class': {'unregister': 1, 'destroy': 0, 'major_owned': 0, 'class_null': 1},
 'unregister-class': {'unregister': 1, 'destroy': 1, 'major_owned': 0, 'class_null': 1},
 'module-register-fail': {'ret': -16,
                          'register': 1,
                          'unregister': 0,
                          'pci_register': 0,
                          'major_owned': 0},
 'module-pci-fail': {'ret': -5,
                     'register': 1,
                     'unregister': 1,
                     'pci_register': 1,
                     'class_calls': 0,
                     'major_owned': 0},
 'module-no-boards': {'ret': 0,
                      'register': 1,
                      'unregister': 1,
                      'pci_unregister': 1,
                      'destroy': 0,
                      'major_owned': 0},
 'module-with-board': {'ret': 0,
                       'register': 1,
                       'unregister': 1,
                       'pci_unregister': 1,
                       'destroy': 1,
                       'class_null': 1,
                       'major_owned': 0,
                       'boards': 0},
 'module-probe-fail': {'ret': 0,
                       'register': 1,
                       'unregister': 1,
                       'pci_unregister': 1,
                       'class_calls': 1,
                       'destroy': 0,
                       'class_null': 1,
                       'major_owned': 0,
                       'boards': 0,
                       'initial_leaked_lock': 0},
 'two-normal-cycles': {'ret': 0,
                       'register': 2,
                       'unregister': 2,
                       'pci_unregister': 2,
                       'class_calls': 2,
                       'destroy': 2,
                       'class_null': 1,
                       'major_owned': 0,
                       'boards': 0},
 'lookup-empty': {'lookup_found': 0, 'refs0': 0},
 'lookup-found': {'lookup_found': 1, 'refs0': 1},
 'lookup-no-match': {'lookup_found': 0, 'refs0': 0},
 'lookup-after-failure': {'first': -12, 'lookup_found': 0, 'refs0': 0, 'class_null': 1},
 'module-pci-fail-after-probe': {'ret': -5,
                                 'unregister': 1,
                                 'destroy': 1,
                                 'major_owned': 0,
                                 'class_null': 1,
                                 'boards': 0},
 'module-pci-fail-after-class-error': {'ret': -5,
                                       'unregister': 1,
                                       'destroy': 0,
                                       'major_owned': 0,
                                       'class_null': 1,
                                       'boards': 0},
 'probe-unwind-then-insert': {'ret': 0, 'class_calls': 1, 'boards': 1, 'indices': [0, 0, 0]}}

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--baseline-ref',default='5d9ce886bd1c91451e3e0a9c2e2e5ee07e5bcc63');parser.add_argument('--results-dir',type=Path);parser.add_argument('--cc',default='gcc');a=parser.parse_args()
 assert os.geteuid()!=0,'Run as an unprivileged user'
 resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
 if a.results_dir:out=a.results_dir;out.mkdir(mode=0o700,parents=False,exist_ok=False)
 else:out=Path(tempfile.mkdtemp(prefix='hailo-chrdev-lifecycle-'))
 env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1');summary={}
 for kind in ['baseline','candidate']:
  source=subprocess.check_output(['git','show',a.baseline_ref+':linux/pcie/src/pcie.c'],cwd=ROOT,text=True) if kind=='baseline' else (ROOT/'linux/pcie/src/pcie.c').read_text()
  dest=out/kind;dest.mkdir(mode=0o700);unit=(HERE/'prefix.c').read_text()+'\n\n'.join(function(source,n) for n in FUNCTIONS)+'\n'+(HERE/'cases.c').read_text();(dest/'unit.c').write_text(unit)
  cmd=[a.cc,'-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-no-pie','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(dest/'unit.c'),'-o',str(dest/'test')]
  r=subprocess.run(cmd,capture_output=True);(dest/'compile.stdout').write_bytes(r.stdout);(dest/'compile.stderr').write_bytes(r.stderr);assert r.returncode==0,r.stderr.decode();(dest/'COMPILE.json').write_text(json.dumps(cmd)+'\n');rows={}
  (dest/'PRODUCTION-IDENTITIES.json').write_text(json.dumps({'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'functions':{n:hashlib.sha256(function(source,n).encode()).hexdigest() for n in FUNCTIONS}},indent=2)+'\n')
  for name,expected in CASES.items():
   r=subprocess.run([str(dest/'test'),name],env=env,capture_output=True);(dest/(name+'.stdout')).write_bytes(r.stdout);(dest/(name+'.stderr')).write_bytes(r.stderr);assert r.returncode==0,(name,r.returncode,r.stderr.decode());actual=json.loads(r.stdout);target=dict(expected,sem=1,blocked=0,bad_unlock=0,class_error=0,bad_destroy=0,bad_unregister=0);errors=[{'field':k,'expected':v,'actual':actual[k]} for k,v in target.items() if actual[k]!=v]
   if actual['down']!=actual['up']:errors.append({'field':'balanced_down_up','actual':[actual['down'],actual['up']]})
   rows[name]={'PASS':not errors,'violations':errors,'actual':actual}
  summary[kind]={'passed':sum(v['PASS'] for v in rows.values()),'total':len(CASES),'cases':rows}
 (out/'DIFFERENTIAL.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps({'results_directory':str(out),'scores':{k:{'passed':v['passed'],'total':v['total']} for k,v in summary.items()}}))
 assert summary['candidate']['passed']==len(CASES),'Candidate regression failure'
if __name__=='__main__':main()
