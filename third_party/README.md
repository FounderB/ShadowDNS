# third_party

ShadowDNS vendors **libbpf** locally (no root `apt` required):

```bash
./scripts/fetch-libbpf.sh
```

Artifacts land in `libbpf-install/`. The BPF object + skeleton are generated at build time from `/sys/kernel/btf/vmlinux`.
