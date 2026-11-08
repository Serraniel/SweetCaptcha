# Proof-of-work benchmarks

Run on 2026-11-08 by `npm run bench` in `lab/`, Chromium 156, on one desktop machine. This file is generated.

Browser: the widget with 4 workers, median of 5 runs, measured from the challenge reply to the submit request. Native: the Go solver on one thread, as an attacker would start, median of 10. A native solver on all cores, or on a GPU, is faster again, and phones are slower; neither is measured here.

| Level | Work | Browser, 4 workers | Native, 1 thread | Browser ÷ native |
|---|---|---|---|---|
| Base | 14 bits × 48, SHA-256 | 133 ms | 87 ms | 1.5× |
| Checkbox step | 16 bits × 48, SHA-256 | 329 ms | 347 ms | 0.9× |
| Wait path (work only) | 18 bits × 48, SHA-256 | 1420 ms | 1348 ms | 1.1× |
| scrypt option | 4 bits × 16, scrypt N=1024 | 807 ms | 559 ms | 1.4× |
