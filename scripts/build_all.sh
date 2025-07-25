#!/bin/bash

set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p ./build/

echo '### PREPARING ###'
docker build -t ebpf-go-builder -f ./docker/Dockerfile_build .

# see also: "//go:generate" in main.go
docker run --rm -v "$(pwd)":/repo ebpf-go-builder /bin/bash -c "\
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /repo/build/vmlinux.h && \
    go mod tidy && \
    cd /repo/src/ && \
    echo '### GENERATING ###' && \
    go generate && \
    bash /repo/scripts/build_archs.sh"

echo '### DONE ###'
ls -l ./build/
