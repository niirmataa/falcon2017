# Timing Run Note: c1-ct-timing-20260423T-repeat3

This directory records the third pinned-CPU dudect-like timing checkpoint for the `ct_strict` path.

The run was executed in the foreground over SSH, so stdout/stderr were visible in the operator session but were not redirected into a persistent `run.log`. The durable evidence for this run is therefore:

- `command.txt`: exact command line reconstructed from the operator invocation
- `ct-dynamic-timing.json`: machine-readable timing dataset emitted by `ct_timing`
- `ct-dynamic-timing.md`: generated timing summary emitted by `ct_timing`

The absence of `run.log` is a process-recording limitation for this one run, not a missing timing dataset. Later long-running timing campaigns use `nohup` with explicit `run.log` capture.
