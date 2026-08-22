#!/bin/sh
# Inert OCI probe. Not a checker. Not a corpus runner.
set -eu
mode=${1:-ok}
case "$mode" in
  ok)
    printf '%s\n' '{"probe":"ok"}'
    exit 0
    ;;
  network)
    wget -q -T 2 -O /dev/null http://1.1.1.1/ && exit 0
    exit 1
    ;;
  tmpfs-bytes)
    dd if=/dev/zero of=/tmp/blob bs=1024 count=2048
    exit 0
    ;;
  tmpfs-bytes-ok)
    dd if=/dev/zero of=/tmp/blob bs=1024 count=4
    printf '%s\n' '{"probe":"tmpfs-bytes-ok"}'
    exit 0
    ;;
  tmpfs-inodes)
    i=0
    while [ "$i" -lt 200 ]; do
      : > "/tmp/i$i"
      i=$((i + 1))
    done
    exit 0
    ;;
  tmpfs-inodes-ok)
    i=0
    while [ "$i" -lt 8 ]; do
      : > "/tmp/i$i"
      i=$((i + 1))
    done
    printf '%s\n' '{"probe":"tmpfs-inodes-ok"}'
    exit 0
    ;;
  output)
    dd if=/dev/zero bs=65536 count=64
    printf x
    exit 0
    ;;
  output-ok)
    printf '%s\n' '{"probe":"output-ok"}'
    exit 0
    ;;
  deadline)
    sleep 120 &
    sleep 120
    exit 0
    ;;
  deadline-ok)
    sleep 0 &
    wait || true
    printf '%s\n' '{"probe":"deadline-ok"}'
    exit 0
    ;;
  exit2-json)
    printf '%s\n' '{"ok":true,"schema":"not-a-success"}'
    exit 2
    ;;
  *)
    printf '%s\n' "unknown mode" >&2
    exit 64
    ;;
esac
