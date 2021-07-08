### alloc_bprm

#### p 的初始值与 vma->vm_end

```shell
sudo bpftrace --include=linux/mm_types.h \
	--include=uapi/linux/ptrace.h \
	--include=linux/sched.h \
	--include=linux/binfmts.h \
	-e 'kretprobe:alloc_bprm { printf("[%d] %lx - %lx\n", pid, ((struct linux_binprm*)retval)->vma->vm_end, ((struct linux_binprm*)retval)->p) }'
```

![image-20210424230307880](/home/xuanc/文档/CodePratice/ELF/ELFLoaderAnalyser/docs/binprm/image-20210424230307880.png)

根据 `bprm->exec` 的值也可以看到顶部存在一个指针的空余

- 运行 bpftrace

  ```shell
  sudo bpftrace --include=linux/mm_types.h --include=uapi/linux/ptrace.h --include=linux/sched.h --include=linux/binfmts.h -e 'kprobe:bprm_execve { printf("[%d] %s %lx %lx\n", pid, comm, ((struct linux_binprm*)arg0)->p, ((struct linux_binprm*)arg0)->exec ) }'
  ```

- 执行测试命令

  ```shell
  env -i /bin/ls
  ```

  > - 使用 env -i 临时情况环境变量

- 输出的结果为

  ```shell
  Attaching 1 probe...
  [87913] bash 7fffffffe1a7 7fffffffefeb
  [87913] env 7fffffffefe8 7fffffffeff0
  ```

    - 第二列为 ls 进程
        - bprm->vma->vm_end ...f000
        - bprm->p 最初位置：...eff8 (...f000 - 8)
        - bprm->exec 存储了 filename 后： ...eff0 (...eff8 - 8)
        - bprm->p 存储了 filename、envp、argv 后（这里 envp 为空，argv 第一个值仍然为 filename）：...efe8 (...eff8 - 8)