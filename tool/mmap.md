# 动态链接的map处理

## VMA 变化

使用命令：`gdb -x observe-maps-on-mmap.py`，可以查看 vma 的变动

### mprotect系统调用

#### 观测命令

```shell
# 开启EBPF监测
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_mprotect { printf("[%d] start: %llx, len: %lu, prot: %lu\n", pid, args->start, args->len, args->prot); }' | tee call_mprotect.log

# 调用程序
./program

# 根据调用程序输出的 pid，获取函数调用情况
grep '150209' call_mprotect.log

# 查看 /proc/xxx/maps 验证
sudo cat /proc/150209/maps
```

