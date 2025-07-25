# Contribute

## Know-How

You will need:
* Docker for the build-dependencies (*or install Go and the dependencies locally..*)
* Some knowledge about how eBPF works

----

### Docs

* [eBPF Docs](https://docs.ebpf.io/)
* [Portable eBPF-powered Applications](https://ebpf-go.dev/guides/portable-ebpf/)
* [Learning eBPF](https://cilium.isovalent.com/hubfs/Learning-eBPF%20-%20Full%20book.pdf)
* [Cilium Docs](https://docs.cilium.io/en/latest/reference-guides/bpf/)

----

## Build

DEV Build: `bash scripts/build_dev.sh <SRC-DIR>`

Full Build: `make build_all` or `bash scripts/build_all.sh`

We use docker to build the binaries as this provides a clean and reproducible build-environment.

We use [cilium/ebpf bpf2go](https://ebpf-go.dev/guides/getting-started) to [cross-compile the sources](https://ebpf-go.dev/guides/portable-ebpf/#cross-compiling).

This is what happens in the build-process:

1. We build the docker-image from [docker/Dockerfile_build](https://github.com/O-X-L/ebpf-ja4t/blob/latest/docker/Dockerfile_build)
2. Using the [bpftool](https://github.com/libbpf/bpftool) we generate the `build/vmlinux.h` file
3. Download go dependencies
4. Using the [bpf2go tool](https://ebpf-go.dev/guides/portable-ebpf/) we generate the `src/bpf_bpfe[b|l].[o|go]` files (see: `//go:generate` in `main.go`)
5. Then we build the binaries into `build/`

----

## Debug

You can use `bpf_trace_printk(fmt, sizeof(fmt));` to temporarily enable debug-output. See: [eBPF Docs](https://docs.ebpf.io/linux/helper-function/bpf_trace_printk/)

You can read it via: `sudo cat /sys/kernel/tracing/trace | grep bpf_trace_printk`
