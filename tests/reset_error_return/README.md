# Standalone source-subset regression

Run as an ordinary user with Python 3, GCC, ASan and UBSan:

```bash
python3 -B reproduce.py --source-root /path/to/driver --output /new/results
```

The output directory must not exist. The baseline returns nonzero because
the contract assertions fail; the fixed tree passes. Kernel APIs are simulated.
No module is installed/loaded and no physical reset occurs.
