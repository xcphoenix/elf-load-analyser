### `_dl_fixup`

#### 命令

```bash
func=_dl_fixup && target_prog=/usr/lib/ld-linux-x86-64.so.2 && \
echo 'PASSWORD' | \
sudo -S bpftrace -e \
"uretprobe:${target_prog}:${func} { \
    printf(\"[%d] - %s => ret: %lx\n\", pid, comm, retval); \
}"
```

#### 描述

- 入参：`link_map`, 符号在 `.rel.plt` 或 `.rela.plt` (`DT_JMPREL`) 中的下标
- 出参：符号的地址

