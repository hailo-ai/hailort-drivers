# Character-device lifecycle regression

Run as an unprivileged user with Python 3 and GCC supporting ASan/UBSan:

```sh
python3 -B tests/chrdev_lifecycle/test_lifecycle.py
```

`--results-dir` accepts a new directory. Results are retained; existing output
is never overwritten. `--baseline-ref` selects an already-local Git revision.
The default is the hailo8 reference used for this comparison; no network is used.

The test extracts seven unchanged production function bodies. Only the kernel
APIs, intrusive lists and semaphore/atomic operations are simulated. Checks
cover class creation failures, retry, board indices and lookup, registration
failure before/after probe, and normal module cleanup. Baseline violations
are reported separately; a candidate contract failure exits nonzero.

The class-destruction double ignores NULL/error pointers as Linux 6.12 does.
Semaphore blocking is observed using a fixture sentinel; it is not a real
kernel deadlock test. No PCI access, module operation, DMA or hardware runs.
These tests do not replace lockdep, KASAN/KCSAN or kernel fault injection.
