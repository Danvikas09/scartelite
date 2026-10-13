/*
 * StraceLite - a ptrace-based syscall tracer and mini-debugger (x86_64 Linux)
 *
 * Usage: stracelite [options] -- command [args...]
 *        stracelite [options] -p PID
 *
 *  -f            follow fork/vfork/clone (processes AND threads)
 *  -c            print a summary table of syscalls (count, errors, time)
 *  -m            print memory report (RSS, page faults, mmap/brk totals)
 *  -M            dump /proc/PID/maps when a process exits
 *  -e trace=SET  only show syscalls in SET: names (open,read) or categories
 *                file,process,memory,signal,ipc,net
 *  -b NAME       "debugger" breakpoint: stop at entry of syscall NAME
 *  -o FILE       write trace to FILE instead of stderr
 *  -p PID        attach to a running process
 *
 * Course-outcome map (see README.md for details):
 *  CO1 user/kernel boundary, syscalls      -> syscall stop handling, table
 *  CO2 fork/exec/wait, process lifecycle   -> spawn_tracee(), main loop
 *  CO3 signals, process groups, pipes      -> signal-delivery-stop, SIGINT
 *  CO4 virtual memory, page faults, maps   -> read_mem(), mem_report(), maps
 *  CO5 fds, inodes, file I/O               -> fd -> path via /proc/PID/fd
 *  CO6 threads, races, sync                -> PTRACE_O_TRACECLONE, __WALL
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/syscall.h>

#if !defined(__x86_64__)
#error "StraceLite supports x86_64 Linux only (register layout is arch-specific)"
#endif

/* ------------------------------------------------------------------ */
/* Syscall table                                                       */
/* ------------------------------------------------------------------ */
enum { T_NONE, T_INT, T_UINT, T_HEX, T_PTR, T_FD, T_ATFD, T_STR, T_BUF,
       T_RBUF, T_OFLAGS, T_PROT, T_MFLAGS, T_MODE };
enum { C_FILE = 1, C_PROC = 2, C_MEM = 4, C_SIG = 8, C_IPC = 16, C_NET = 32,
       C_OTHER = 64 };

struct sc {
    int nr;
    const char *name;
    int nargs;
    int cat;
    int types[6];
};

static const struct sc table[] = {
    {0,   "read",           3, C_FILE, {T_FD, T_RBUF, T_UINT}},
    {1,   "write",          3, C_FILE, {T_FD, T_BUF, T_UINT}},
    {2,   "open",           3, C_FILE, {T_STR, T_OFLAGS, T_MODE}},
    {3,   "close",          1, C_FILE, {T_FD}},
    {4,   "stat",           2, C_FILE, {T_STR, T_PTR}},
    {5,   "fstat",          2, C_FILE, {T_FD, T_PTR}},
    {6,   "lstat",          2, C_FILE, {T_STR, T_PTR}},
    {8,   "lseek",          3, C_FILE, {T_FD, T_INT, T_INT}},
    {9,   "mmap",           6, C_MEM,  {T_PTR, T_UINT, T_PROT, T_MFLAGS, T_FD, T_HEX}},
    {10,  "mprotect",       3, C_MEM,  {T_PTR, T_UINT, T_PROT}},
    {11,  "munmap",         2, C_MEM,  {T_PTR, T_UINT}},
    {12,  "brk",            1, C_MEM,  {T_PTR}},
    {13,  "rt_sigaction",   4, C_SIG,  {T_INT, T_PTR, T_PTR, T_UINT}},
    {14,  "rt_sigprocmask", 4, C_SIG,  {T_INT, T_PTR, T_PTR, T_UINT}},
    {16,  "ioctl",          3, C_FILE, {T_FD, T_HEX, T_PTR}},
    {17,  "pread64",        4, C_FILE, {T_FD, T_PTR, T_UINT, T_INT}},
    {20,  "writev",         3, C_FILE, {T_FD, T_PTR, T_INT}},
    {21,  "access",         2, C_FILE, {T_STR, T_INT}},
    {22,  "pipe",           1, C_IPC,  {T_PTR}},
    {24,  "sched_yield",    0, C_OTHER, {0}},
    {32,  "dup",            1, C_FILE, {T_FD}},
    {33,  "dup2",           2, C_FILE, {T_FD, T_FD}},
    {35,  "nanosleep",      2, C_OTHER, {T_PTR, T_PTR}},
    {39,  "getpid",         0, C_PROC, {0}},
    {41,  "socket",         3, C_NET,  {T_INT, T_INT, T_INT}},
    {42,  "connect",        3, C_NET,  {T_FD, T_PTR, T_INT}},
    {56,  "clone",          5, C_PROC, {T_HEX, T_PTR, T_PTR, T_PTR, T_HEX}},
    {57,  "fork",           0, C_PROC, {0}},
    {58,  "vfork",          0, C_PROC, {0}},
    {59,  "execve",         3, C_PROC, {T_STR, T_PTR, T_PTR}},
    {60,  "exit",           1, C_PROC, {T_INT}},
    {61,  "wait4",          4, C_PROC, {T_INT, T_PTR, T_INT, T_PTR}},
    {62,  "kill",           2, C_SIG,  {T_INT, T_INT}},
    {63,  "uname",          1, C_OTHER, {T_PTR}},
    {72,  "fcntl",          3, C_FILE, {T_FD, T_INT, T_HEX}},
    {79,  "getcwd",         2, C_FILE, {T_PTR, T_UINT}},
    {80,  "chdir",          1, C_FILE, {T_STR}},
    {82,  "rename",         2, C_FILE, {T_STR, T_STR}},
    {83,  "mkdir",          2, C_FILE, {T_STR, T_MODE}},
    {84,  "rmdir",          1, C_FILE, {T_STR}},
    {87,  "unlink",         1, C_FILE, {T_STR}},
    {89,  "readlink",       3, C_FILE, {T_STR, T_PTR, T_UINT}},
    {102, "getuid",         0, C_PROC, {0}},
    {110, "getppid",        0, C_PROC, {0}},
    {158, "arch_prctl",     2, C_PROC, {T_HEX, T_PTR}},
    {186, "gettid",         0, C_PROC, {0}},
    {202, "futex",          6, C_IPC,  {T_PTR, T_INT, T_INT, T_PTR, T_PTR, T_INT}},
    {217, "getdents64",     3, C_FILE, {T_FD, T_PTR, T_UINT}},
    {218, "set_tid_address",1, C_PROC, {T_PTR}},
    {228, "clock_gettime",  2, C_OTHER, {T_INT, T_PTR}},
    {231, "exit_group",     1, C_PROC, {T_INT}},
    {234, "tgkill",         3, C_SIG,  {T_INT, T_INT, T_INT}},
    {257, "openat",         4, C_FILE, {T_ATFD, T_STR, T_OFLAGS, T_MODE}},
    {258, "mkdirat",        3, C_FILE, {T_ATFD, T_STR, T_MODE}},
    {262, "newfstatat",     4, C_FILE, {T_ATFD, T_STR, T_PTR, T_HEX}},
    {263, "unlinkat",       3, C_FILE, {T_ATFD, T_STR, T_HEX}},
    {273, "set_robust_list",2, C_PROC, {T_PTR, T_UINT}},
    {293, "pipe2",          2, C_IPC,  {T_PTR, T_HEX}},
    {302, "prlimit64",      4, C_PROC, {T_INT, T_INT, T_PTR, T_PTR}},
    {318, "getrandom",      3, C_OTHER, {T_PTR, T_UINT, T_HEX}},
    {334, "rseq",           4, C_PROC, {T_PTR, T_UINT, T_INT, T_HEX}},
    {435, "clone3",         2, C_PROC, {T_PTR, T_UINT}},
};
#define NTABLE (sizeof table / sizeof table[0])
#define MAXNR 512
static const struct sc *by_nr[MAXNR];

static void init_table(void)
{
    for (size_t i = 0; i < NTABLE; i++)
        by_nr[table[i].nr] = &table[i];
}

/* ------------------------------------------------------------------ */
/* Global options / state                                              */
/* ------------------------------------------------------------------ */
static FILE *out;
static int opt_follow, opt_summary, opt_mem, opt_maps, opt_attach;
static int g_prefix;                 /* print [pid N] prefix */
static const char *opt_break;        /* syscall name to break on */
static int break_next;               /* "next" command in prompt */
static int cat_mask;                 /* -e trace=... categories */
static char *name_filter[64];
static int n_name_filter;
static volatile sig_atomic_t g_sigint;

struct stat_ent { long count, errors; double secs; };
static struct stat_ent stats[MAXNR + 1];
static long n_signals;
static long mmap_calls, mmap_bytes, munmap_calls, munmap_bytes, brk_calls;

#define MAXT 1024
struct tracee {
    pid_t pid;
    int used, in_sys, fresh, show;
    long nr;
    unsigned long long a[6];
    char as[6][192];                 /* decoded args captured at entry */
    struct timespec t0;
    const struct sc *sc;
};
static struct tracee tr[MAXT];
static int live;

static struct tracee *get_tracee(pid_t pid, int create)
{
    struct tracee *free_slot = NULL;
    for (int i = 0; i < MAXT; i++) {
        if (tr[i].used && tr[i].pid == pid)
            return &tr[i];
        if (!tr[i].used && !free_slot)
            free_slot = &tr[i];
    }
    if (!create || !free_slot)
        return NULL;
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->used = 1;
    free_slot->pid = pid;
    free_slot->fresh = 1;
    live++;
    return free_slot;
}

static void drop_tracee(struct tracee *t)
{
    t->used = 0;
    live--;
}

/* ------------------------------------------------------------------ */
/* Reading tracee memory (CO4: address spaces are separate!)          */
/* ------------------------------------------------------------------ */
static ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec l = { buf, len }, r = { (void *)addr, len };
    ssize_t n = process_vm_readv(pid, &l, 1, &r, 1, 0);
    if (n >= 0)
        return n;
    /* fallback: PTRACE_PEEKDATA, one word at a time */
    size_t got = 0;
    while (got < len) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, addr + got, 0);
        if (errno)
            break;
        size_t chunk = len - got < 8 ? len - got : 8;
        memcpy((char *)buf + got, &w, chunk);
        got += chunk;
    }
    return got ? (ssize_t)got : -1;
}

static size_t esc(char *o, size_t n, size_t max, unsigned char c)
{
    if (n + 6 >= max)
        return n;
    switch (c) {
    case '\n': o[n++] = '\\'; o[n++] = 'n'; break;
    case '\t': o[n++] = '\\'; o[n++] = 't'; break;
    case '\r': o[n++] = '\\'; o[n++] = 'r'; break;
    case '"':  o[n++] = '\\'; o[n++] = '"'; break;
    case '\\': o[n++] = '\\'; o[n++] = '\\'; break;
    default:
        if (c >= 32 && c < 127)
            o[n++] = c;
        else
            n += snprintf(o + n, max - n, "\\x%02x", c);
    }
    return n;
}

#define MAXSTR 64
static void read_str(pid_t pid, unsigned long addr, char *out_s, size_t max)
{
    if (!addr) { snprintf(out_s, max, "NULL"); return; }
    size_t o = 0;
    int n = 0, trunc = 0, done = 0;
    out_s[o++] = '"';
    for (unsigned long off = 0; !done; off += 8) {
        errno = 0;
        long w = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0);
        if (errno) {
            if (n == 0) { snprintf(out_s, max, "0x%lx", addr); return; }
            break;
        }
        unsigned char *b = (unsigned char *)&w;
        for (int i = 0; i < 8; i++) {
            if (!b[i]) { done = 1; break; }
            if (n >= MAXSTR) { trunc = 1; done = 1; break; }
            o = esc(out_s, o, max, b[i]);
            n++;
        }
    }
    out_s[o++] = '"';
    if (trunc) { o += snprintf(out_s + o, max - o, "..."); }
    out_s[o] = 0;
}

static void read_buf(pid_t pid, unsigned long addr, unsigned long len,
                     char *out_s, size_t max)
{
    unsigned char tmp[32];
    size_t want = len < sizeof tmp ? len : sizeof tmp;
    if (!addr) { snprintf(out_s, max, "NULL"); return; }
    ssize_t n = read_mem(pid, addr, tmp, want);
    if (n < 0) { snprintf(out_s, max, "0x%lx", addr); return; }
    size_t o = 0;
    out_s[o++] = '"';
    for (ssize_t i = 0; i < n; i++)
        o = esc(out_s, o, max, tmp[i]);
    out_s[o++] = '"';
    if (len > want) o += snprintf(out_s + o, max - o, "...");
    out_s[o] = 0;
}

/* ------------------------------------------------------------------ */
/* Argument formatting                                                 */
/* ------------------------------------------------------------------ */
struct fl { unsigned long v; const char *n; };

static void fmt_flags(char *o, size_t max, unsigned long v,
                      const struct fl *f, int nf, const char *zero)
{
    size_t n = 0;
    o[0] = 0;
    for (int i = 0; i < nf; i++)
        if ((v & f[i].v) == f[i].v && f[i].v) {
            n += snprintf(o + n, max - n, "%s%s", n ? "|" : "", f[i].n);
            v &= ~f[i].v;
        }
    if (v)
        n += snprintf(o + n, max - n, "%s0x%lx", n ? "|" : "", v);
    if (!n)
        snprintf(o, max, "%s", zero);
}

static const struct fl oflags[] = {
    {O_CREAT, "O_CREAT"}, {O_EXCL, "O_EXCL"}, {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"}, {O_NONBLOCK, "O_NONBLOCK"},
    {O_DIRECTORY, "O_DIRECTORY"}, {O_CLOEXEC, "O_CLOEXEC"},
};
static const struct fl protf[] = {
    {1, "PROT_READ"}, {2, "PROT_WRITE"}, {4, "PROT_EXEC"},
};
static const struct fl mapf[] = {
    {0x01, "MAP_SHARED"}, {0x02, "MAP_PRIVATE"}, {0x10, "MAP_FIXED"},
    {0x20, "MAP_ANONYMOUS"}, {0x4000, "MAP_NORESERVE"},
    {0x20000, "MAP_STACK"}, {0x8000, "MAP_POPULATE"},
};

static void fmt_arg(struct tracee *t, int type, unsigned long long v,
                    char *o, size_t max)
{
    switch (type) {
    case T_INT:   snprintf(o, max, "%d", (int)v); break;
    case T_UINT:  snprintf(o, max, "%llu", v); break;
    case T_MODE:  snprintf(o, max, "0%llo", v); break;
    case T_HEX:   snprintf(o, max, "0x%llx", v); break;
    case T_PTR:
        if (v) snprintf(o, max, "0x%llx", v);
        else   snprintf(o, max, "NULL");
        break;
    case T_ATFD:
        if ((int)v == -100) { snprintf(o, max, "AT_FDCWD"); break; }
        /* fallthrough */
    case T_FD: {
        char p[64], path[160];
        if ((int)v < 0) { snprintf(o, max, "%d", (int)v); break; }
        snprintf(p, sizeof p, "/proc/%d/fd/%d", t->pid, (int)v);
        ssize_t n = readlink(p, path, sizeof path - 1);
        if (n > 0) { path[n] = 0; snprintf(o, max, "%d<%s>", (int)v, path); }
        else snprintf(o, max, "%d", (int)v);
        break;
    }
    case T_STR:   read_str(t->pid, v, o, max); break;
    case T_OFLAGS: {
        const char *acc[] = {"O_RDONLY", "O_WRONLY", "O_RDWR", "O_?"};
        char rest[128];
        fmt_flags(rest, sizeof rest, v & ~3UL, oflags, 7, "");
        snprintf(o, max, "%s%s%s", acc[v & 3], rest[0] ? "|" : "", rest);
        break;
    }
    case T_PROT:  fmt_flags(o, max, v, protf, 3, "PROT_NONE"); break;
    case T_MFLAGS: fmt_flags(o, max, v, mapf, 7, "0"); break;
    default:      snprintf(o, max, "0x%llx", v);
    }
}

static const char *errname(int e)
{
    switch (e) {
    case EPERM: return "EPERM";   case ENOENT: return "ENOENT";
    case ESRCH: return "ESRCH";   case EINTR: return "EINTR";
    case EIO: return "EIO";       case ENOEXEC: return "ENOEXEC";
    case EBADF: return "EBADF";   case ECHILD: return "ECHILD";
    case EAGAIN: return "EAGAIN"; case ENOMEM: return "ENOMEM";
    case EACCES: return "EACCES"; case EFAULT: return "EFAULT";
    case EEXIST: return "EEXIST"; case ENOTDIR: return "ENOTDIR";
    case EISDIR: return "EISDIR"; case EINVAL: return "EINVAL";
    case EMFILE: return "EMFILE"; case ENOSPC: return "ENOSPC";
    case EPIPE: return "EPIPE";   case ENOSYS: return "ENOSYS";
    case ENOTEMPTY: return "ENOTEMPTY";
    default: return "E?";
    }
}

/* ------------------------------------------------------------------ */
/* Filtering (-e trace=...)                                            */
/* ------------------------------------------------------------------ */
static void parse_filter(const char *spec)
{
    char *s = strdup(spec), *save = NULL;
    if (strncmp(s, "trace=", 6) == 0) memmove(s, s + 6, strlen(s + 6) + 1);
    for (char *tok = strtok_r(s, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!strcmp(tok, "file")) cat_mask |= C_FILE;
        else if (!strcmp(tok, "process")) cat_mask |= C_PROC;
        else if (!strcmp(tok, "memory")) cat_mask |= C_MEM;
        else if (!strcmp(tok, "signal")) cat_mask |= C_SIG;
        else if (!strcmp(tok, "ipc")) cat_mask |= C_IPC;
        else if (!strcmp(tok, "net")) cat_mask |= C_NET;
        else if (n_name_filter < 64) name_filter[n_name_filter++] = strdup(tok);
    }
    free(s);
}

static int want(const struct sc *sc)
{
    if (!cat_mask && !n_name_filter) return 1;
    if (!sc) return 0;
    if (sc->cat & cat_mask) return 1;
    for (int i = 0; i < n_name_filter; i++)
        if (!strcmp(name_filter[i], sc->name)) return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* /proc helpers (CO4 / CO5)                                           */
/* ------------------------------------------------------------------ */
static void cat_proc(pid_t pid, const char *what, FILE *to, const char *prefix)
{
    char p[64], line[512];
    snprintf(p, sizeof p, "/proc/%d/%s", pid, what);
    FILE *f = fopen(p, "r");
    if (!f) { fprintf(to, "%s(cannot read %s)\n", prefix, p); return; }
    while (fgets(line, sizeof line, f))
        fprintf(to, "%s%s", prefix, line);
    fclose(f);
}

static void mem_report(pid_t pid, FILE *to)
{
    char p[64], line[256];
    unsigned long minflt = 0, majflt = 0;
    snprintf(p, sizeof p, "/proc/%d/stat", pid);
    FILE *f = fopen(p, "r");
    if (f) {
        if (fgets(line, sizeof line, f)) {
            char *rp = strrchr(line, ')');
            if (rp)
                sscanf(rp + 2, "%*c %*d %*d %*d %*d %*d %*u %lu %*u %lu",
                       &minflt, &majflt);
        }
        fclose(f);
    }
    fprintf(to, "[mem pid %d] minor page faults=%lu  major page faults=%lu\n",
            pid, minflt, majflt);
    snprintf(p, sizeof p, "/proc/%d/status", pid);
    f = fopen(p, "r");
    if (!f) return;
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, "VmSize", 6) || !strncmp(line, "VmRSS", 5) ||
            !strncmp(line, "VmData", 6) || !strncmp(line, "VmStk", 5) ||
            !strncmp(line, "Threads", 7))
            fprintf(to, "[mem pid %d] %s", pid, line);
    fclose(f);
}

/* ------------------------------------------------------------------ */
/* Tiny debugger prompt (gdb-lite)                                     */
/* ------------------------------------------------------------------ */
static void print_regs(const struct user_regs_struct *r, FILE *to)
{
    fprintf(to, "rip=%016llx rsp=%016llx rbp=%016llx\n", r->rip, r->rsp, r->rbp);
    fprintf(to, "rax=%016llx rbx=%016llx rcx=%016llx\n", r->rax, r->rbx, r->rcx);
    fprintf(to, "rdx=%016llx rsi=%016llx rdi=%016llx\n", r->rdx, r->rsi, r->rdi);
    fprintf(to, "r8 =%016llx r9 =%016llx r10=%016llx\n", r->r8, r->r9, r->r10);
    fprintf(to, "orig_rax=%lld eflags=%016llx\n", (long long)r->orig_rax, r->eflags);
}

/* returns 1 if user asked to detach/quit */
static int debug_prompt(struct tracee *t)
{
    char line[256];
    struct user_regs_struct r;
    fprintf(stderr, "\n*** stopped pid %d at entry of %s ***\n", t->pid,
            t->sc ? t->sc->name : "syscall");
    fprintf(stderr, "commands: regs | maps | mem ADDR LEN | str ADDR | fd | "
                    "status | next | cont | quit\n");
    for (;;) {
        fprintf(stderr, "(slite) ");
        if (!fgets(line, sizeof line, stdin)) return 0;
        char cmd[32] = "";
        unsigned long a = 0, n = 64;
        sscanf(line, "%31s %lx %lu", cmd, &a, &n);
        if (!strcmp(cmd, "regs")) {
            ptrace(PTRACE_GETREGS, t->pid, 0, &r);
            print_regs(&r, stderr);
        } else if (!strcmp(cmd, "maps")) {
            cat_proc(t->pid, "maps", stderr, "  ");
        } else if (!strcmp(cmd, "mem")) {
            unsigned char buf[256];
            if (n > sizeof buf) n = sizeof buf;
            ssize_t got = read_mem(t->pid, a, buf, n);
            if (got < 0) { fprintf(stderr, "cannot read 0x%lx\n", a); continue; }
            for (ssize_t i = 0; i < got; i += 16) {
                fprintf(stderr, "%016lx: ", a + i);
                for (ssize_t j = i; j < i + 16 && j < got; j++)
                    fprintf(stderr, "%02x ", buf[j]);
                fprintf(stderr, "\n");
            }
        } else if (!strcmp(cmd, "str")) {
            char s[256];
            read_str(t->pid, a, s, sizeof s);
            fprintf(stderr, "%s\n", s);
        } else if (!strcmp(cmd, "fd")) {
            char p[64], path[256], lnk[256];
            snprintf(p, sizeof p, "/proc/%d/fd", t->pid);
            for (int fd = 0; fd < 64; fd++) {
                snprintf(path, sizeof path, "%s/%d", p, fd);
                ssize_t k = readlink(path, lnk, sizeof lnk - 1);
                if (k > 0) { lnk[k] = 0; fprintf(stderr, "  %d -> %s\n", fd, lnk); }
            }
        } else if (!strcmp(cmd, "status")) {
            mem_report(t->pid, stderr);
        } else if (!strcmp(cmd, "next") || !strcmp(cmd, "n")) {
            break_next = 1; return 0;
        } else if (!strcmp(cmd, "cont") || !strcmp(cmd, "c")) {
            break_next = 0; return 0;
        } else if (!strcmp(cmd, "quit") || !strcmp(cmd, "q")) {
            return 1;
        } else if (cmd[0]) {
            fprintf(stderr, "unknown command '%s'\n", cmd);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Printing one syscall                                                */
/* ------------------------------------------------------------------ */
static double ts_diff(struct timespec a, struct timespec b)
{
    return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
}

static void print_call(struct tracee *t, long ret, int has_ret)
{
    char line[1600], name[32];
    size_t o = 0;
    const struct sc *sc = t->sc;
    int nargs = sc ? sc->nargs : 6;

    if (sc) snprintf(name, sizeof name, "%s", sc->name);
    else snprintf(name, sizeof name, "syscall_%ld", t->nr);

    if (g_prefix) o += snprintf(line + o, sizeof line - o, "[pid %5d] ", t->pid);
    o += snprintf(line + o, sizeof line - o, "%s(", name);
    for (int i = 0; i < nargs; i++) {
        if (sc && sc->types[i] == T_MODE && !t->as[i][0]) continue;
        if (i) o += snprintf(line + o, sizeof line - o, ", ");
        if (sc && sc->types[i] == T_RBUF) {
            char b[192];
            if (has_ret && ret > 0) read_buf(t->pid, t->a[i], ret, b, sizeof b);
            else snprintf(b, sizeof b, "0x%llx", t->a[i]);
            o += snprintf(line + o, sizeof line - o, "%s", b);
        } else {
            o += snprintf(line + o, sizeof line - o, "%s", t->as[i]);
        }
    }
    o += snprintf(line + o, sizeof line - o, ")");
    if (!has_ret) {
        snprintf(line + o, sizeof line - o, " = ?");
    } else if ((unsigned long)ret > (unsigned long)-4096) {
        int e = (int)-ret;
        snprintf(line + o, sizeof line - o, " = -1 %s (%s)", errname(e), strerror(e));
    } else if (t->nr == SYS_mmap || t->nr == SYS_brk) {
        snprintf(line + o, sizeof line - o, " = 0x%lx", ret);
    } else {
        snprintf(line + o, sizeof line - o, " = %ld", ret);
    }
    fprintf(out, "%s\n", line);
}

/* ------------------------------------------------------------------ */
/* Syscall entry / exit                                                */
/* ------------------------------------------------------------------ */
static int syscall_entry(struct tracee *t, const struct user_regs_struct *r)
{
    t->nr = r->orig_rax;
    t->a[0] = r->rdi; t->a[1] = r->rsi; t->a[2] = r->rdx;
    t->a[3] = r->r10; t->a[4] = r->r8;  t->a[5] = r->r9;
    t->sc = (t->nr >= 0 && t->nr < MAXNR) ? by_nr[t->nr] : NULL;
    t->show = want(t->sc);
    clock_gettime(CLOCK_MONOTONIC, &t->t0);

    int nargs = t->sc ? t->sc->nargs : 6;
    for (int i = 0; i < nargs; i++) {
        int ty = t->sc ? t->sc->types[i] : T_HEX;
        if (ty == T_RBUF) { t->as[i][0] = 0; continue; }
        if (ty == T_BUF)
            read_buf(t->pid, t->a[i], t->a[2], t->as[i], sizeof t->as[i]);
        else
            fmt_arg(t, ty, t->a[i], t->as[i], sizeof t->as[i]);
    }

    /* like strace: mode only matters when a file may be created */
    if (t->sc && (t->nr == SYS_open || t->nr == SYS_openat)) {
        int fi = t->nr == SYS_open ? 1 : 2;
        if (!(t->a[fi] & (O_CREAT | O_TMPFILE))) t->as[fi + 1][0] = 0;
    }

    if (t->nr == SYS_exit || t->nr == SYS_exit_group) {
        /* process still alive here: last chance to inspect it (CO4) */
        if (opt_mem) mem_report(t->pid, out);
        if (opt_maps) { fprintf(out, "[maps pid %d]\n", t->pid);
                        cat_proc(t->pid, "maps", out, "  "); }
        if (t->show) print_call(t, 0, 0);
        if (t->nr < MAXNR) { stats[t->nr].count++; }
    }

    if ((opt_break && t->sc && !strcmp(t->sc->name, opt_break)) || break_next)
        return debug_prompt(t);
    return 0;
}

static void syscall_exit(struct tracee *t, const struct user_regs_struct *r)
{
    struct timespec t1;
    long ret = (long)r->rax;
    int idx = (t->nr >= 0 && t->nr < MAXNR) ? (int)t->nr : MAXNR;
    clock_gettime(CLOCK_MONOTONIC, &t1);

    stats[idx].count++;
    stats[idx].secs += ts_diff(t->t0, t1);
    if ((unsigned long)ret > (unsigned long)-4096) stats[idx].errors++;
    else {
        if (t->nr == SYS_mmap)   { mmap_calls++; mmap_bytes += t->a[1]; }
        if (t->nr == SYS_munmap) { munmap_calls++; munmap_bytes += t->a[1]; }
    }
    if (t->nr == SYS_brk) brk_calls++;

    if (t->show) print_call(t, ret, 1);
}

/* ------------------------------------------------------------------ */
/* Summary (-c)                                                        */
/* ------------------------------------------------------------------ */
static void print_summary(void)
{
    double total = 0;
    long tc = 0, te = 0;
    int order[MAXNR + 1], n = 0;
    for (int i = 0; i <= MAXNR; i++)
        if (stats[i].count) { order[n++] = i; total += stats[i].secs;
                              tc += stats[i].count; te += stats[i].errors; }
    for (int i = 0; i < n; i++)            /* sort by time, desc */
        for (int j = i + 1; j < n; j++)
            if (stats[order[j]].secs > stats[order[i]].secs) {
                int x = order[i]; order[i] = order[j]; order[j] = x;
            }
    fprintf(out, "\n%% time     seconds   calls  errors  syscall\n");
    fprintf(out, "------ ----------- ------- ------- ----------------\n");
    for (int i = 0; i < n; i++) {
        int k = order[i];
        char nm[32];
        if (k < MAXNR && by_nr[k]) snprintf(nm, sizeof nm, "%s", by_nr[k]->name);
        else snprintf(nm, sizeof nm, "syscall_%d", k);
        fprintf(out, "%6.2f %11.6f %7ld %7ld  %s\n",
                total > 0 ? 100.0 * stats[k].secs / total : 0.0,
                stats[k].secs, stats[k].count, stats[k].errors, nm);
    }
    fprintf(out, "------ ----------- ------- ------- ----------------\n");
    fprintf(out, "100.00 %11.6f %7ld %7ld  total\n", total, tc, te);
    fprintf(out, "signals delivered to tracees: %ld\n", n_signals);
    if (opt_mem)
        fprintf(out, "memory syscalls: mmap=%ld (%ld bytes)  munmap=%ld (%ld bytes)  brk=%ld\n",
                mmap_calls, mmap_bytes, munmap_calls, munmap_bytes, brk_calls);
}

/* ------------------------------------------------------------------ */
/* Starting / attaching (CO2: fork + exec + wait)                      */
/* ------------------------------------------------------------------ */
static long trace_opts(void)
{
    long o = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC;
    if (opt_follow)
        o |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    return o;
}

static pid_t spawn_tracee(char **argv)
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid == 0) {
        /* child: ask to be traced, stop so parent can set options, exec */
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        raise(SIGSTOP);
        execvp(argv[0], argv);
        perror(argv[0]);
        _exit(127);
    }
    int st;
    waitpid(pid, &st, 0);                 /* child's SIGSTOP */
    if (!WIFSTOPPED(st)) { fprintf(stderr, "child did not stop\n"); exit(1); }
    ptrace(PTRACE_SETOPTIONS, pid, 0, trace_opts());
    struct tracee *t = get_tracee(pid, 1);
    t->fresh = 0;
    return pid;
}

static void attach_to(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { perror("PTRACE_ATTACH"); exit(1); }
    int st;
    waitpid(pid, &st, __WALL);
    ptrace(PTRACE_SETOPTIONS, pid, 0, trace_opts());
    struct tracee *t = get_tracee(pid, 1);
    t->fresh = 0;
}

static void detach_all(void)
{
    for (int i = 0; i < MAXT; i++) {
        if (!tr[i].used) continue;
        kill(tr[i].pid, SIGSTOP);
        int st;
        waitpid(tr[i].pid, &st, __WALL);
        ptrace(PTRACE_DETACH, tr[i].pid, 0, 0);
        kill(tr[i].pid, SIGCONT);
        fprintf(stderr, "detached from %d\n", tr[i].pid);
    }
}

static void on_sigint(int s) { (void)s; g_sigint = 1; }

static void usage(void)
{
    fprintf(stderr,
        "usage: stracelite [-f] [-c] [-m] [-M] [-e trace=SET] [-b SYSCALL] [-o FILE]\n"
        "                  ( -p PID | -- command [args...] )\n");
    exit(2);
}

/* ------------------------------------------------------------------ */
/* main loop                                                           */
/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    int c;
    pid_t attach_pid = 0;
    out = stderr;
    init_table();

    while ((c = getopt(argc, argv, "+fcmMe:b:o:p:h")) != -1) {
        switch (c) {
        case 'f': opt_follow = 1; break;
        case 'c': opt_summary = 1; break;
        case 'm': opt_mem = 1; break;
        case 'M': opt_maps = 1; break;
        case 'e': parse_filter(optarg); break;
        case 'b': opt_break = optarg; break;
        case 'o': out = fopen(optarg, "w");
                  if (!out) { perror(optarg); return 1; } break;
        case 'p': attach_pid = atoi(optarg); opt_attach = 1; break;
        default:  usage();
        }
    }
    if (!opt_attach && optind >= argc) usage();
    if (opt_follow) g_prefix = 1;
    setvbuf(out, NULL, _IOLBF, 0);

    /* CO3: SIGINT handler WITHOUT SA_RESTART so waitpid() returns EINTR */
    struct sigaction sa = { .sa_handler = on_sigint };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    pid_t root = opt_attach ? (attach_to(attach_pid), attach_pid)
                            : spawn_tracee(&argv[optind]);
    ptrace(PTRACE_SYSCALL, root, 0, 0);

    int exit_status = 0;
    while (live > 0) {
        int st;
        pid_t p = waitpid(-1, &st, __WALL);
        if (p < 0) {
            if (errno == EINTR) {
                if (g_sigint && opt_attach) { detach_all(); break; }
                continue;              /* spawned mode: tracee gets SIGINT too */
            }
            break;
        }
        struct tracee *t = get_tracee(p, 1);
        if (!t) continue;

        if (WIFEXITED(st)) {
            fprintf(out, "%s+++ exited with %d +++\n", "", WEXITSTATUS(st));
            if (p == root) exit_status = WEXITSTATUS(st);
            drop_tracee(t);
            continue;
        }
        if (WIFSIGNALED(st)) {
            fprintf(out, "+++ killed by %s +++\n", strsignal(WTERMSIG(st)));
            if (p == root) exit_status = 128 + WTERMSIG(st);
            drop_tracee(t);
            continue;
        }
        if (!WIFSTOPPED(st)) continue;

        int sig = WSTOPSIG(st), ev = st >> 16, inject = 0;

        if (sig == (SIGTRAP | 0x80)) {                 /* syscall stop */
            struct user_regs_struct r;
            ptrace(PTRACE_GETREGS, p, 0, &r);
            t->in_sys = !t->in_sys;
            if (t->in_sys) {
                if (syscall_entry(t, &r)) {            /* user typed quit */
                    detach_all();
                    break;
                }
            } else {
                syscall_exit(t, &r);
            }
        } else if (ev) {                               /* ptrace event */
            unsigned long msg = 0;
            ptrace(PTRACE_GETEVENTMSG, p, 0, &msg);
            if (ev == PTRACE_EVENT_FORK || ev == PTRACE_EVENT_VFORK ||
                ev == PTRACE_EVENT_CLONE) {
                const char *k = ev == PTRACE_EVENT_FORK ? "fork" :
                                ev == PTRACE_EVENT_VFORK ? "vfork" : "clone/thread";
                get_tracee((pid_t)msg, 1);
                fprintf(out, "[pid %5d] --- %s: new task %lu ---\n", p, k, msg);
            } else if (ev == PTRACE_EVENT_EXEC) {
                fprintf(out, "%s--- exec: image replaced ---\n",
                        g_prefix ? "            " : "");
            }
        } else if (sig == SIGSTOP && t->fresh) {       /* initial stop of new task */
            t->fresh = 0;
        } else {                                       /* signal-delivery-stop */
            siginfo_t si;
            n_signals++;
            if (ptrace(PTRACE_GETSIGINFO, p, 0, &si) == 0)
                fprintf(out, "%s--- %s {si_signo=%d, si_code=%d, si_pid=%d} ---\n",
                        g_prefix ? "            " : "", strsignal(sig),
                        si.si_signo, si.si_code, si.si_pid);
            inject = sig;                              /* pass it on to tracee */
        }
        ptrace(PTRACE_SYSCALL, p, 0, inject);
    }

    if (opt_summary) print_summary();
    if (out != stderr) fclose(out);
    return exit_status;
}
