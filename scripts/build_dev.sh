#!/bin/bash

set -eo pipefail

if [ -z "$1" ]
then
  SRC_DIR='src/'
else
  SRC_DIR="$1"
fi

set -u

cd "$(dirname "$0")/.."

mkdir -p ./build/

echo '### PREPARING ###'
if [[ "$(docker images -f reference=ebpf-go-builder-dev | wc -l)" == "1" ]]
then
  docker build -t ebpf-go-builder-dev -f ./docker/Dockerfile_build .
  docker run -v "$(pwd)":/repo ebpf-go-builder-dev /bin/bash -c "\
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > /repo/build/vmlinux.h && \
    go mod tidy"
fi

OUT_FILE='build/ja4t_collector'

# see also: "//go:generate" in main.go
docker run --rm -v "$(pwd)":/repo ebpf-go-builder-dev /bin/bash -c "\
    cd /repo/${SRC_DIR} && \
    echo '### GENERATING ###' && \
    go generate && \
    echo '### BUILDING ###' && \
    go build -C /repo/${SRC_DIR} -o '/repo/${OUT_FILE}' -buildvcs=false"

echo "DONE: ${OUT_FILE}"
