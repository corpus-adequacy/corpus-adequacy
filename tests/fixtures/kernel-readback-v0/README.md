# Kernel-interface read-back samples

Exact bytes the kernel returned on 2026-09-18 inside one throwaway container of the pinned
toolchain image `sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2`,
with no network and the owned resource profile's limits: `--memory 4294967296
--memory-swap 4294967296 --pids-limit 512 --cpu-period 100000 --cpu-quota 100000
--ulimit nofile=1024:1024`. Kernel `7.0.12-linuxkit` (Docker Desktop's VM).

`proc-limits` is `/proc/self/limits`; the others are the cgroup v2 files of the same name.
They are format fixtures for `measurements/kernel_readback.py`, not evidence that any
measured candidate was bounded.
