# StraceLite — a syscall tracer & mini-debugger

A `ptrace`-based tool (like a small `strace` + a tiny `gdb`) for x86_64 Linux,
written in C. One source file: `stracelite.c` (~600 lines).

## Build & run
```
make                       # builds ./stracelite and the test programs
./demo.sh                  # one demo per course outcome
./stracelite -- ls /tmp    # trace a command
./stracelite -p 1234       # attach to a running process (may need sudo)
```

| Flag | Meaning |
|------|---------|
| `-f` | follow `fork`/`vfork`/`clone` — child processes **and threads** |
| `-c` | summary table: calls, errors, time per syscall |
| `-m` | memory report at exit: RSS, page faults, mmap/munmap/brk totals |
| `-M` | dump `/proc/PID/maps` just before each process exits |
| `-e trace=SET` | filter by name (`open,read`) or category (`file,process,memory,signal,ipc,net`) |
| `-b NAME` | **debugger mode**: stop at entry of syscall NAME and open a prompt |
| `-o FILE` | write trace to a file |

Debugger prompt commands: `regs`, `maps`, `mem ADDR LEN`, `str ADDR`, `fd`,
`status`, `next` (stop at the next syscall), `cont`, `quit` (detach).

Example session:
```
./stracelite -b openat -- cat /etc/hostname
(slite) regs        # CPU registers at the syscall boundary
(slite) str 7ffd... # read the filename out of the tracee's memory
(slite) maps        # its virtual address space
(slite) cont
```

## How it works (30-second version)
1. `fork()` a child. Child calls `ptrace(PTRACE_TRACEME)`, raises `SIGSTOP`, then `execvp()`s the target.
2. Parent `waitpid()`s, sets `PTRACE_O_*` options, then loops on `ptrace(PTRACE_SYSCALL)`.
3. The kernel stops the tracee **twice per syscall** (entry and exit). At each stop
   `PTRACE_GETREGS` gives the syscall number (`orig_rax`), args (`rdi rsi rdx r10 r8 r9`) and, at exit, the return value (`rax`).
4. Pointers (filenames, buffers) are in the *tracee's* address space, so they are copied with `process_vm_readv` / `PTRACE_PEEKDATA`.
5. Signals stop the tracee too (signal-delivery-stop); we print them and re-inject them.

## Syllabus coverage

| CO | Topic from syllabus | Where in StraceLite |
|----|--------------------|---------------------|
| **CO1** | User space vs kernel space, system calls, command execution journey | Every line of output *is* a user→kernel crossing. Table of ~60 syscalls; `execve` shown as the "command journey" (shell → fork → exec). `-c` shows where time is spent in kernel services. |
| **CO2** | fork/exec/wait, lifecycle, pitfalls | `spawn_tracee()` itself is the fork+exec+wait pattern; `-f` shows parent/child trees, `wait4`, exit status, `+++ exited +++`, `killed by SIG`. Zombie/orphan behaviour visible with `t_fork`. |
| **CO3** | Pipes, signals, handlers, process groups/job control | `pipe2` + fd paths (`pipe:[862]`); signal-delivery-stop printing `si_signo/si_pid`; own `sigaction` SIGINT handler (no `SA_RESTART`, so `waitpid` returns `EINTR`); Ctrl-C reaches tracee via shared foreground process group; detach on SIGINT in `-p` mode. |
| **CO4** | Virtual memory, page tables, demand paging, COW, maps, memory tools | Reads another process's memory; `-m` prints minor/major page faults from `/proc/PID/stat`; `-M`/`maps` shows the address-space layout; `t_mem` shows 4000+ faults when touching a fresh `mmap`, and COW in the forked child. |
| **CO5** | Inodes, fds, VFS, file I/O syscalls, mmap I/O | fd numbers are resolved to paths via `/proc/PID/fd` (`3</tmp/file>`); open flags decoded; `-e trace=file`; `mmap` with `MAP_SHARED`/file fd shows memory-mapped I/O. |
| **CO6** | Threads, mutexes, futex, races | `PTRACE_O_TRACECLONE` + `__WALL` traces every thread; `t_threads` shows `clone3` and `futex` (what `pthread_mutex_lock` becomes under contention). |

## Viva cheat-sheet
* **Why two stops per syscall?** Entry (args valid) and exit (return value valid); I toggle an `in_sys` flag per task.
* **Why `PTRACE_O_TRACESYSGOOD`?** Sets bit 7 on SIGTRAP so syscall-stops aren't confused with real SIGTRAPs.
* **Why `PTRACE_O_TRACEEXEC`?** Without it the kernel sends an extra SIGTRAP after `execve`, which I'd wrongly inject and kill the process.
* **Why can't I just dereference the pointer?** Separate virtual address spaces (CO4) — must ask the kernel to copy.
* **Why `PTRACE_O_EXITKILL`?** If the tracer dies, tracees are killed instead of running untraced.
* **Why `__WALL`?** Threads are "clone children" that plain `waitpid` ignores.
* **Why is `-1 ENOENT` useful?** Kernel returns `-errno` in `rax`; values in `[-4095,-1]` are errors.

## Limitations / ideas to extend
* x86_64 only (register names are arch-specific). ARM64 would use `x8`/`x0..x5` and `PTRACE_GETREGSET`.
* Partial syscall table — unknown ones print as `syscall_N(...)` with hex args.
* Extension ideas: software breakpoints (`int3` patching via `PTRACE_POKETEXT`), `PTRACE_SINGLESTEP`, `-e inject=`, fault injection (make `openat` fail), JSON output, a per-thread timing view with a mutex-protected stats thread (CO6).
* Container note: if `ptrace` fails with `EPERM`, run `docker run --cap-add=SYS_PTRACE` or set `/proc/sys/kernel/yama/ptrace_scope` to 0.
