"""Exercise exact production C bodies with deterministic software dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
from extractor import function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--revision', help='Optional local Git revision; never changes the checkout')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(argv, label):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'argv': list(map(str, argv)), 'exit': result.returncode})
        (out / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        return result

    sources = {}
    for path in ['linux/pcie/src/pcie.c', 'linux/pcie/src/fops.c']:
        if args.revision:
            sources[path] = subprocess.check_output(['git', '-C', str(root), 'show', args.revision + ':' + path])
        else:
            sources[path] = (root / path).read_bytes()
    pcie = sources['linux/pcie/src/pcie.c'].decode()
    fops = sources['linux/pcie/src/fops.c'].decode()
    bodies = [function(fops, 'boot_irq_handler'), function(pcie, 'wait_for_firmware_completion'),
              function(pcie, 'hailo_pcie_soft_reset')]
    (out / 'production.inc').write_text('\n\n'.join(bodies) + '\n')
    executable = out / 'fixture'
    result = run(['gcc', '-std=gnu11', '-g', '-O1', '-Wall', '-Wextra', '-Werror',
                  '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                  '-I' + str(out), HERE / 'fixture.c', '-o', executable], 'compile')
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace'))
    # (name, timing: 0=absent/1=during request/2=during wait, boot, stale count, repeats)
    cases = [('immediate_ack', 1, 1, 0, 1), ('wait_ack', 2, 1, 0, 1),
             ('missing_ack', 0, 1, 0, 1), ('boot_missing_after_ack', 1, 0, 0, 1),
             ('stale_count_without_new_ack', 0, 1, 1, 1),
             ('two_immediate_requests', 1, 1, 0, 2), ('stale_count_and_new_ack', 1, 1, 1, 1)]
    rows = []
    for name, timing, boot, stale, repeats in cases:
        result = run([executable, timing, boot, stale, repeats], name)
        if result.returncode:
            raise RuntimeError((name, result.returncode, result.stderr.decode(errors='replace')))
        observed = list(map(int, result.stdout.split()))
        acknowledged = timing != 0
        expected = [0 if acknowledged and boot else -110, repeats, repeats,
                    repeats if acknowledged else 0, repeats, 0]
        # Unit conversion belongs to an independent correction. Keep its
        # observations but assert only the completion-ordering contract.
        ordering = [observed[i] for i in [0, 1, 2, 3, 4, 7]]
        rows.append({'name': name, 'observed': observed, 'expected_ordering': expected, 'pass': ordering == expected})
    report = {'scope': 'exact source subsets with simulated kernel/completion/MMIO dependencies; no hardware',
              'source_revision': args.revision, 'assertion_scope': 'completion ordering, return status and stage counts; conversion/tick fields are observations only', 'source_sha256': {k: hashlib.sha256(v).hexdigest() for k, v in sources.items()},
              'fields': ['status', 'requests', 'waits', 'boot_polls', 'rearms', 'conversions', 'jiffies', 'remaining_completions'],
              'passed': sum(row['pass'] for row in rows), 'total': len(rows), 'cases': rows}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['passed'] == report['total'] else 1


if __name__ == '__main__':
    sys.exit(main())
