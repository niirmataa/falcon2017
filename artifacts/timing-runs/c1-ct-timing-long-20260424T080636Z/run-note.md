# Timing Run Note: c1-ct-timing-long-20260424T080636Z

This directory records the first longer pinned-CPU dudect-like timing checkpoint for the `ct_strict` path.

Run properties:

- host: Ubuntu GNU/Linux under VMware
- CPU pinning: `taskset -c 0`
- samples per class: `16384`
- expand batch: `8`
- sign batch: `8`
- stdout/stderr: captured in `run.log`

Durable evidence in this directory:

- `command.txt`: exact invocation
- `run.log`: compiler warnings and process output captured from the run
- `ct-dynamic-timing.json`: machine-readable timing dataset emitted by `ct_timing`
- `ct-dynamic-timing.md`: generated timing summary emitted by `ct_timing`

Key result:

- `sign_ct_strict_falcon1024_none` crossed the dudect notice threshold with `t = -9.751`
- the result is below the configured strong threshold `|t| >= 10.0`, but close enough that it blocks any stronger `C1` wording
- this signal did not appear in the three earlier 4096-sample checkpoints, which reinforces that the current VMware host is not a stable final timing platform
