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

You can read it via: `sudo cat /sys/kernel/tracing/trace | grep BPF` (if you add prefix like `[eBPF]` to the message)

NOTE: `bpf_trace_printk` can only take 3 format-parameters.

**Examples:**

* Format IPv4

  ```c
  const char log_ip4[] = "[eBPF] IP4: %pI4\n";
  bpf_trace_printk(log_ip4, sizeof(log_ip4), &ip4->saddr);
  // bpf_trace_printk: [eBPF] IP4: 127.0.0.1
  ```

* Format IPv6

  ```c
  const char log_ip6[] = "[eBPF] IP6: %pI6\n";
  bpf_trace_printk(log_ip6, sizeof(log_ip6), &ip6->saddr);
  // bpf_trace_printk: [eBPF] IP6: fe80:0000:0000:0000:c87f:acff:fe69:287a
  ```

* Write hex of bytes

  ```c
  const char log_ip6_p1[] = "[eBPF] IP6: Parts 1+2 (0x%x 0x%x)\n";
  bpf_trace_printk(log_ip6_p1, sizeof(log_ip6_p1), bpf_ntohl(ip6o.addr[0]), bpf_ntohl(ip6o.addr[1]));
  const char log_ip6_p2[] = "[eBPF] IP6: Parts 3+4 (0x%x 0x%x)\n";
  bpf_trace_printk(log_ip6_p2, sizeof(log_ip6_p2), bpf_ntohl(ip6o.addr[2]), bpf_ntohl(ip6o.addr[3]));
  // bpf_trace_printk: [eBPF] IP6: Parts 1+2 (0xfe800000 0x0)
  // bpf_trace_printk: [eBPF] IP6: Parts 3+4 (0xc87facff 0xfe69287a)
  ```
