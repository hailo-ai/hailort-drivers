# Soft-reset completion ordering regression

Run as an ordinary user with Python 3, GCC, ASan and UBSan:

```sh
python3 -B tests/reset_completion_order/reproduce.py --source-root . --output /new/results
```

The output directory must not exist. Add `--revision REVISION` to examine an
older local Git revision without changing the checkout. No other test suite
or Hailo SDK is required. The extractor compiles the exact production wait
helper, soft-reset method and boot IRQ handler against minimal C dependencies.

A response is delivered synchronously during the simulated request write to
exercise the lost-completion boundary deterministically. Seven scenarios cover
immediate and wait-time responses, no response, boot-poll failure, an initial
stale counter and two successive requests. Status and stage/completion counts
are asserted; conversion counts and jiffies are recorded as observations only.
The separate timeout-unit correction is not included or required by this suite.

No real kernel, MMIO, firmware, device open, ioctl, reset or module loading is
performed. Moving reinitialization only avoids clearing an immediate response.
It does not distinguish an old late IRQ, drain pending IRQs, serialize every
reset caller, qualify recovery or prove DMA retirement.
