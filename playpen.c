#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/limits.h>
#include <pwd.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/timerfd.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <time.h>

#include <seccomp.h>

#define SYSCALL_NAME_MAX 30
#define STACK_SIZE 512 * 1024

#define CHECK_POSIX(rc,...) check_posix(__FILE__,__LINE__,rc,__VA_ARGS__)
#define MOUNTX(source, target, fstype, mountflags, data) mountx(__FILE__,__LINE__,source,target,fstype,mountflags,data)

#define EXIT_TIMEOUT 3
#define EXIT_MB_S 4

typedef struct {
  int argc;
  char **argv;
} args;

static void check(int rc) {
    if (rc < 0) errx(EXIT_FAILURE, "%s", strerror(-rc));
}

__attribute__((format(printf, 4, 5))) static void check_posix(char *file, int line, intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1)
    {
      fprintf(stderr, "%s:%d: ", file, line);
      verr(EXIT_FAILURE, fmt, args);
    }
    va_end(args);
}

__attribute__((format(printf, 2, 3))) static bool check_eagain(intmax_t rc, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (rc == -1 && errno != EAGAIN) verr(EXIT_FAILURE, fmt, args);
    va_end(args);
    return rc == -1 && errno == EAGAIN;
}

static char *join_path(const char *left, const char *right) {
    char *dst;
    CHECK_POSIX(asprintf(&dst, "%s/%s", left, right), "asprintf");
    return dst;
}

static void mountx(char *file, int line, const char *source, const char *target, 
                   const char *filesystemtype, unsigned long mountflags, const void *data) {
    check_posix(file,line,mount(source, target, filesystemtype, mountflags, data),
                "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

struct bind_list {
    struct bind_list *next;
    bool read_only;
    char arg[];
};

static struct bind_list *bind_list_alloc(const char *arg, bool read_only) {
    size_t len = strlen(arg);
    struct bind_list *next = malloc(sizeof(struct bind_list) + len + 1);
    if (!next) err(EXIT_FAILURE, "malloc");

    next->next = NULL;
    next->read_only = read_only;
    strcpy(next->arg, arg);
    return next;
}

static void bind_list_apply(const char *root, struct bind_list *list) {
    for (; list; list = list->next) {
        char *dst = join_path(root, list->arg);
        // Only use MS_REC with writable mounts to work around a kernel bug:
        // https://bugzilla.kernel.org/show_bug.cgi?id=24912
        MOUNTX(list->arg, dst, "bind", MS_BIND | (list->read_only ? 0 : MS_REC), NULL);
        if (list->read_only)
            MOUNTX(list->arg, dst, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
        free(dst);
    }
}

static void bind_list_free(struct bind_list *list) {
    while (list) {
        struct bind_list *next = list->next;
        free(list);
        list = next;
    }
}

static void epoll_add(int epoll_fd, int fd, uint32_t events) {
    struct epoll_event event = { .data.fd = fd, .events = events };
    CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event), "epoll_ctl");
}

static void copy_to_stdstream(int in_fd, int out_fd) {
    uint8_t buffer[BUFSIZ];
    ssize_t n = read(in_fd, buffer, sizeof buffer);
    if (check_eagain(n, "read")) return;
    CHECK_POSIX(write(out_fd, buffer, (size_t)n), "write");
}

static int get_syscall_nr(const char *name) {
    int result = seccomp_syscall_resolve_name(name);
    if (result == __NR_SCMP_ERROR) {
        errx(EXIT_FAILURE, "non-existent syscall: %s", name);
    }
    return result;
}

static void set_rlimit(int resource, long value) {
   struct rlimit rlim;
   if (value < 0)
     return;
   rlim.rlim_cur = (rlim_t) value;
   rlim.rlim_max = (rlim_t) value;
   CHECK_POSIX(setrlimit((unsigned int) resource, &rlim), "set_rlimit %d", resource);
}

static void drop_capabilities() {
  // once we drop the privileges, we should never regain them
  // by e.g. executing a suid-root binary
  CHECK_POSIX(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "ptrcl set no new privs");

  for (int i = 0; i <= 63; i++) {
    int cur = prctl(PR_CAPBSET_READ, i, 0, 0, 0);
    if (cur < 0)
    {
      if (errno == EINVAL)
        continue;
      else
        err(EXIT_FAILURE,"prctl(PR_CAPBSET_READ, %d, 0, 0, 0)", i);
    }

    if (cur != 0)
    {
      int code = prctl(PR_CAPBSET_DROP, i, 0, 0, 0);
      if (code < 0 && errno != EINVAL)
        err(EXIT_FAILURE, "prctl(PR_CAPBSET_DROP, %d, 0, 0, 0)",i);
    }
  }
}

static double calculate_mbs(double old_mbs, struct timespec *last_time, double max_mbs)
{
  // get interval, in ms
  struct timespec current;
  CHECK_POSIX(clock_gettime(CLOCK_MONOTONIC, &current), "clock_gettime");
  time_t diff_ms = (current.tv_sec - last_time->tv_sec) * 1000;
  diff_ms += (current.tv_nsec - last_time->tv_nsec) / 1.0e6; // convert nanoseconds to miliseconds
  double elapsed_secs = ( (double) diff_ms ) / 1000.0;
  if (elapsed_secs < 0) err(EXIT_FAILURE, "elapsed secs < 0 : %f", elapsed_secs);
  if (elapsed_secs < 0.001) return old_mbs; // do not set current time if elapsed time is very small
  *last_time = current;

  DIR *dir = opendir("/proc");
  if (!dir) err(EXIT_FAILURE, "opendir /proc");
  struct dirent *dp;
  while( (dp = readdir(dir)) ) {
    if (dp->d_name[0] < '0' || dp->d_name[0] > '9') continue;
    char *end;
    strtol(dp->d_name, &end, 10);
    if (*end == '\0') {
      // read smaps
      char *path;
      CHECK_POSIX(asprintf(&path, "/proc/%s/smaps", dp->d_name), "asprintf");
      FILE *stream = fopen(path, "r");
      if (NULL == stream)
        err(EXIT_FAILURE, "fopen(%s)", path);

      // unfortunately this is the only way to get the Pss
      char *line = NULL;
      size_t len;
      ssize_t read;
      while( (read = getline(&line, &len, stream)) != -1 ) {
        char *pss = strstr(line, "Pss:");
        if (NULL != pss) {
          pss += 4;
          while (*pss == ' ') pss++;
          if (*pss < '0' || *pss > '9') errx(EXIT_FAILURE, "pss string '%s': expected number", line);

          char *end_pss;
          int pss_kb = (int)strtol(pss, &end_pss, 10);
          if (pss_kb < 0) errx(EXIT_FAILURE, "negative pss: '%d'", pss_kb);
          if (end_pss == pss) errx(EXIT_FAILURE, "cannot parse number for pss '%s'", line);

          double pss_mb = ( (double) pss_kb ) / 1024.0;
          old_mbs += pss_mb * elapsed_secs;
          if (old_mbs >= max_mbs) {
            free(line);
            fclose(stream);
            free(path);
            closedir(dir);
            return old_mbs; // we don't need to loop in here anymore
          }
        }
      }

      free(line);
      fclose(stream);
      free(path);
    }
  }
  closedir(dir);

  return old_mbs;
}

_Noreturn static void usage(FILE *out) {
    fprintf(out, "usage: %s [options] [root] [command ...]\n", program_invocation_short_name);
    fputs("Options:\n"
          " -h, --help                  display this help\n"
          " -v, --version               display version\n"
          " -p, --mount-proc            mount /proc in the container\n"
          "     --mount-dev             mount /dev as devtmpfs in the container\n"
          "     --mount-tmpfs           mount tmpfs containers\n"
          "     --mount-minimal         mount minimal /dev\n"
          "     --rlimit-as=VALUE       sets the rlimit max virtual memory of the process, in bytes\n"
          "     --rlimit-cpu=VALUE      sets the rlimit max CPU time, in seconds\n"
          "     --rlimit-fsize=VALUE    sets the rlimit max file size of a single file, in bytes\n"
          "     --rlimit-nofile=VALUE   sets the rlimit max number of open files\n"
          "     --rlimit-nproc=VALUE    sets the rlimit max number of open processes\n"
          "     --rlimit-nice=VALUE     sets the rlimit min number of nice (set as 20 + nice_value. seee rlimit manpage)\n"
          " -x, --max-mbs               sets the maximum accumulated MB-s that the process can use\n"
          " -e, --mbs-check-every       sets the internal, in ms, to check the memory usage for the MB-s accumulator\n"
          " -b, --bind                  bind mount a read-only directory in the container\n"
          " -B, --bind-rw               bind mount a directory in the container\n"
          " -u, --user=USER             the user to run the program as\n"
          " -n, --hostname=NAME         the hostname to set the container to\n"
          " -t, --timeout=INTEGER       how long the container is allowed to run\n"
          " -m, --memory-limit=LIMIT    the memory limit of the container\n"
          " -s, --syscalls=LIST         comma-separated whitelist of syscalls\n"
          " -S, --syscalls-file=PATH    whitelist file containing one syscall name per line\n"
          " -l, --learn=PATH            allow unwhitelisted syscalls and append them to a file\n",
          out);

    exit(out == stderr ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    CHECK_POSIX(flags, "fcntl");
    CHECK_POSIX(fcntl(fd, F_SETFL, flags | O_NONBLOCK), "fcntl");
}

// Mark any extra file descriptors `CLOEXEC`. Only `stdin`, `stdout` and `stderr` are left open.
static void prevent_leaked_file_descriptors() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) err(EXIT_FAILURE, "opendir /proc/self/fd");
    struct dirent *dp;
    while ((dp = readdir(dir))) {
        char *end;
        int fd = (int)strtol(dp->d_name, &end, 10);
        if (*end == '\0' && fd > 2 && fd != dirfd(dir)) {
            CHECK_POSIX(ioctl(fd, FIOCLEX), "ioctl");
        }
    }
    closedir(dir);
}

static long strtolx_positive(const char *s, const char *what) {
    char *end;
    errno = 0;
    long result = strtol(s, &end, 10);
    if (errno) errx(EXIT_FAILURE, "%s is too large", what);
    if (*end != '\0' || result < 0)
        errx(EXIT_FAILURE, "%s must be a positive integer", what);
    return result;
}

static void do_trace(const struct signalfd_siginfo *si, bool *trace_init, FILE *learn) {
    int status;
    if (waitpid((pid_t)si->ssi_pid, &status, WNOHANG) != (pid_t)si->ssi_pid)
        errx(EXIT_FAILURE, "waitpid");

    if (WIFEXITED(status) || WIFSIGNALED(status) || !WIFSTOPPED(status))
        errx(EXIT_FAILURE, "unexpected ptrace event");

    int inject_signal = 0;
    if (*trace_init) {
        int signal = WSTOPSIG(status);
        if (signal != SIGTRAP || !(status & PTRACE_EVENT_SECCOMP))
            inject_signal = signal;
        else {
            errno = 0;
#ifdef __x86_64__
            long syscall = ptrace(PTRACE_PEEKUSER, si->ssi_pid, sizeof(long)*ORIG_RAX);
#else
            long syscall = ptrace(PTRACE_PEEKUSER, si->ssi_pid, sizeof(long)*ORIG_EAX);
#endif
            if (errno) err(EXIT_FAILURE, "ptrace");
            char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)syscall);
            if (!name) errx(EXIT_FAILURE, "seccomp_syscall_resolve_num_arch");

            rewind(learn);
            char line[SYSCALL_NAME_MAX];
            while (fgets(line, sizeof line, learn)) {
                char *pos;
                if ((pos = strchr(line, '\n'))) *pos = '\0';
                if (!strcmp(name, line)) {
                    name = NULL;
                    break;
                }
            }

            if (name) {
                fprintf(learn, "%s\n", name);
                free(name);
            }
        }
    } else {
        CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, si->ssi_pid, 0, PTRACE_O_TRACESECCOMP), "ptrace");
        *trace_init = true;
    }
    CHECK_POSIX(ptrace(PTRACE_CONT, si->ssi_pid, 0, inject_signal), "ptrace");
}

static void handle_signal(int sig_fd, pid_t child_fd,
                          bool *trace_init, FILE *learn) {
    struct signalfd_siginfo si;
    ssize_t bytes_r = read(sig_fd, &si, sizeof(si));
    CHECK_POSIX(bytes_r, "read");

    if (bytes_r != sizeof(si))
        errx(EXIT_FAILURE, "read the wrong amount of bytes");

    switch (si.ssi_signo) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        kill(child_fd, SIGKILL);
        errx(EXIT_FAILURE, "interrupted, stopping early");
    }

    if (si.ssi_signo != SIGCHLD)
        errx(EXIT_FAILURE, "got an unexpected signal");

    switch (si.ssi_code) {
    case CLD_EXITED:
        if (si.ssi_status) {
            warnx("application terminated with error code %d", si.ssi_status);
        }
        exit(si.ssi_status);
    case CLD_KILLED:
    case CLD_DUMPED:
        errx(EXIT_FAILURE, "application terminated abnormally with signal %d (%s)",
             si.ssi_status, strsignal(si.ssi_status));
    case CLD_TRAPPED:
        do_trace(&si, trace_init, learn);
    case CLD_STOPPED:
    default:
        break;
    }
}


static int sandbox(void *args);

int main(int argc, char **argv) {
    prevent_leaked_file_descriptors();

    args cmd_args;
    cmd_args.argc = argc;
    cmd_args.argv = argv;
    char sandbox_stack[STACK_SIZE]; //reuse our own stack for the child

    int flags = SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET;
    pid_t pid = clone(sandbox, sandbox_stack + STACK_SIZE, flags, &cmd_args);
    CHECK_POSIX(pid, "clone");
    int status = 0;
    waitpid(pid, &status, 0);
    int exitstatus = WEXITSTATUS(status);
    return exitstatus;
}

int sandbox(void *my_args) {
    args *args = my_args;
    int argc = args->argc;
    char **argv = args->argv;

    bool mount_proc = false;
    bool mount_dev = false;
    bool mount_tmpfs = false;
    bool mount_minimal_dev = false;
    long rlimit_as = -1,
         rlimit_fsize = -1,
         rlimit_nofile = -1,
         rlimit_nproc = -1,
         rlimit_nice = -1,
				 rlimit_cpu = -1;
    long max_mbs = -1,
         mbs_check_every = 250;
    const char *username = "nobody";
    const char *hostname = "playpen";
    long timeout = 0;
    long memory_limit = 128;
    struct bind_list *binds = NULL, *binds_tail = NULL;
    char *syscalls = NULL;
    const char *syscalls_file = NULL;
    const char *learn_name = NULL;

    static const struct option opts[] = {
        { "help",          no_argument,       0, 'h' },
        { "version",       no_argument,       0, 'v' },
        { "mount-proc",    no_argument,       0, 'p' },
        { "mount-dev",     no_argument,       0, 0x100 },
        { "mount-tmpfs",   no_argument,       0, 0x101 },
        { "mount-minimal", no_argument,       0, 0x102 },
        { "rlimit-as",     required_argument, 0, 0x200 },
        { "rlimit-fsize",  required_argument, 0, 0x201 },
        { "rlimit-nofile", required_argument, 0, 0x202 },
        { "rlimit-nproc",  required_argument, 0, 0x203 },
        { "rlimit-nice",   required_argument, 0, 0x204 },
        { "rlimit-cpu",    required_argument, 0, 0x205 },
        { "max-mbs",       required_argument, 0, 'x' },
        { "mbs-check-every",required_argument,0, 'e' },
        { "bind",          required_argument, 0, 'b' },
        { "bind-rw",       required_argument, 0, 'B' },
        { "user",          required_argument, 0, 'u' },
        { "hostname",      required_argument, 0, 'n' },
        { "timeout",       required_argument, 0, 't' },
        { "memory-limit",  required_argument, 0, 'm' },
        { "syscalls",      required_argument, 0, 's' },
        { "syscalls-file", required_argument, 0, 'S' },
        { "learn",         required_argument, 0, 'l' },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int opt = getopt_long(argc, argv, "hvpx:e:b:B:u:n:t:m:d:s:S:l:", opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':
            usage(stdout);
        case 'v':
            printf("%s %s\n", program_invocation_short_name, VERSION);
            return 0;
        case 'p':
            mount_proc = true;
            break;
        case 0x100:
            mount_dev = true;
            break;
        case 0x101:
            mount_tmpfs = true;
            break;
        case 0x102:
            mount_minimal_dev = true;
            break;
        case 0x200:
            rlimit_as = strtolx_positive(optarg, "rlimit-as");
            break;
        case 0x201:
            rlimit_fsize = strtolx_positive(optarg, "rlimit-fsize");
            break;
        case 0x202:
            rlimit_nofile = strtolx_positive(optarg, "rlimit-nofile");
            break;
        case 0x203:
            rlimit_nproc = strtolx_positive(optarg, "rlimit-nproc");
            break;
        case 0x204:
            rlimit_nice = strtolx_positive(optarg, "rlimit-nice");
            break;
        case 0x205:
            rlimit_cpu = strtolx_positive(optarg, "rlimit-cpu");
            break;
        case 'x':
            max_mbs = strtolx_positive(optarg, "max-mbs");
            break;
        case 'e':
            mbs_check_every = strtolx_positive(optarg, "mbs-check-every");
            break;
        case 'b':
        case 'B':
            if (binds) {
                binds_tail->next = bind_list_alloc(optarg, opt == 'b');
                binds_tail = binds_tail->next;
            } else {
                binds = binds_tail = bind_list_alloc(optarg, opt == 'b');
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'n':
            hostname = optarg;
            break;
        case 't':
            timeout = strtolx_positive(optarg, "timeout");
            break;
        case 'm':
            memory_limit = strtolx_positive(optarg, "memory limit");
            break;
        case 's':
            syscalls = optarg;
            break;
        case 'S':
            syscalls_file = optarg;
            break;
        case 'l':
            learn_name = optarg;
            break;
        default:
            usage(stderr);
        }
    }

    if (argc - optind < 2) {
        usage(stderr);
    }

    const char *root = argv[optind];
    optind++;

    scmp_filter_ctx ctx = seccomp_init(learn_name ? SCMP_ACT_TRACE(0) : SCMP_ACT_KILL);
    if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

    if (syscalls_file) {
        char name[SYSCALL_NAME_MAX];
        FILE *file = fopen(syscalls_file, "r");
        if (!file) err(EXIT_FAILURE, "failed to open syscalls file: %s", syscalls_file);
        while (fgets(name, sizeof name, file)) {
            char *pos;
            if ((pos = strchr(name, '\n'))) *pos = '\0';
            check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(name), 0));
        }
        fclose(file);
    }

    check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0));

    if (syscalls) {
        for (char *s_ptr = syscalls, *saveptr; ; s_ptr = NULL) {
            const char *syscall = strtok_r(s_ptr, ",", &saveptr);
            if (!syscall) break;
            check(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(syscall), 0));
        }
    }

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    CHECK_POSIX(epoll_fd, "epoll_create1");

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    CHECK_POSIX(sigprocmask(SIG_BLOCK, &mask, NULL), "sigprocmask");

    int sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    CHECK_POSIX(sig_fd, "signalfd");

    epoll_add(epoll_fd, sig_fd, EPOLLIN);

    int pipe_in[2];
    int pipe_out[2];
    int pipe_err[2];
    CHECK_POSIX(pipe(pipe_in), "pipe");
    CHECK_POSIX(pipe(pipe_out), "pipe");
    set_non_blocking(pipe_out[0]);
    CHECK_POSIX(pipe(pipe_err), "pipe");
    set_non_blocking(pipe_err[0]);

    int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO,
                       &(struct epoll_event){ .data.fd = STDIN_FILENO, .events = EPOLLIN });
    if (rc == -1 && errno != EPERM) err(EXIT_FAILURE, "epoll_ctl");
    const bool stdin_non_epoll = rc == -1;

    epoll_add(epoll_fd, pipe_out[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_err[0], EPOLLIN);
    epoll_add(epoll_fd, pipe_in[1], EPOLLET | EPOLLOUT);

    pid_t pid = fork();
    CHECK_POSIX(pid, "fork");

    if (pid == 0) {
        dup2(pipe_in[0], STDIN_FILENO);
        close(pipe_in[0]);
        close(pipe_in[1]);

        dup2(pipe_out[1], STDOUT_FILENO);
        close(pipe_out[0]);
        close(pipe_out[1]);

        dup2(pipe_err[1], STDERR_FILENO);
        close(pipe_err[0]);
        close(pipe_err[1]);

        // Kill this process if the parent dies. This is not a replacement for killing the sandboxed
        // processes via a control group as it is not inherited by child processes, but is more
        // robust when the sandboxed process is not allowed to fork.
        CHECK_POSIX(prctl(PR_SET_PDEATHSIG, SIGKILL), "prctl");

        // Wait until the scope unit is set up before moving on. This also ensures that the parent
        // didn't die before `prctl` was called.
        uint8_t ready;
        CHECK_POSIX(read(STDIN_FILENO, &ready, sizeof ready), "read");

        CHECK_POSIX(sethostname(hostname, strlen(hostname)), "sethostname");

        // avoid propagating mounts to or from the parent's mount namespace
        MOUNTX(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        // turn directory into a bind mount
        MOUNTX(root, root, "bind", MS_BIND|MS_REC, NULL);

        // re-mount as read-only
        MOUNTX(root, root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

        if (mount_proc) {
            char *mnt = join_path(root, "proc");
            MOUNTX(NULL, mnt, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
            free(mnt);
        }

        if (mount_dev) {
            char *mnt = join_path(root, "dev");
            MOUNTX(NULL, mnt, "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
            free(mnt);
        }

        if (mount_minimal_dev) {
          char *devices[] = { "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", NULL };
          for (int i = 0; devices[i] != NULL; i++)
          {
            char *mnt = join_path(root, devices[i]);
            if (access(mnt, F_OK) < 0)
            {
              errx(EXIT_FAILURE,"The file '%s' was not found inside the chroot jail", mnt);
            }
            CHECK_POSIX(mount(devices[i], mnt, NULL, MS_BIND, NULL), "mount");
            free(mnt);
          }
        }

        if (mount_tmpfs)
        {
          char *shm = join_path(root, "dev/shm");
          if (mount(NULL, shm, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
              if (errno != ENOENT) {
                  err(EXIT_FAILURE, "mounting /dev/shm failed");
              }
          }
          free(shm);
        }

        if (mount_tmpfs)
        {
          char *tmp = join_path(root, "tmp");
          if (mount(NULL, tmp, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) {
              if (errno != ENOENT) {
                  err(EXIT_FAILURE, "mounting /tmp failed");
              }
          }
          free(tmp);
        }

        set_rlimit(RLIMIT_AS, rlimit_as);
        set_rlimit(RLIMIT_FSIZE, rlimit_fsize);
        set_rlimit(RLIMIT_NOFILE, rlimit_nofile);
        set_rlimit(RLIMIT_NPROC, rlimit_nproc);
        set_rlimit(RLIMIT_NICE, rlimit_nice);
        set_rlimit(RLIMIT_CPU, rlimit_cpu);

        bind_list_apply(root, binds);

        // preserve a reference to the target directory
        CHECK_POSIX(chdir(root), "chdir");

        // make the working directory into the root of the mount namespace
        MOUNTX(".", "/", NULL, MS_MOVE, NULL);

        // chroot into the root of the mount namespace
        CHECK_POSIX(chroot("."), "chroot into `%s` failed", root);
        CHECK_POSIX(chdir("/"), "entering chroot `%s` failed", root);

        errno = 0;
        struct passwd *pw = getpwnam(username);
        if (!pw) {
            if (errno) {
                err(EXIT_FAILURE, "getpwnam");
            } else {
                errx(EXIT_FAILURE, "no passwd entry for username %s", username);
            }
        }

        // check if exists
        if (access(pw->pw_dir, F_OK) >= 0)
        {
          if (mount_tmpfs)
            MOUNTX(NULL, pw->pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

          // switch to the user's home directory as a login shell would
          CHECK_POSIX(chdir(pw->pw_dir), "chdir");
        } else {
          CHECK_POSIX(chdir("/"), "chdir");
        }

        drop_capabilities();
        // create a new session
        CHECK_POSIX(setsid(), "setsid");

        CHECK_POSIX(initgroups(username, pw->pw_gid), "initgroups");
        CHECK_POSIX(setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid), "setresgid");
        CHECK_POSIX(setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid), "setresuid");

        char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
        char *env[] = {path, NULL, NULL, NULL, NULL};
        if ((asprintf(env + 1, "HOME=%s", pw->pw_dir) < 0 ||
             asprintf(env + 2, "USER=%s", username) < 0 ||
             asprintf(env + 3, "LOGNAME=%s", username) < 0)) {
            errx(EXIT_FAILURE, "asprintf");
        }

        if (learn_name) CHECK_POSIX(ptrace(PTRACE_TRACEME, 0, NULL, NULL), "ptrace");

        check(seccomp_load(ctx));
        CHECK_POSIX(execvpe(argv[optind], argv + optind, env), "execvpe");
    }

    if (max_mbs) {
        // avoid propagating mounts to or from the parent's mount namespace
        MOUNTX(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

        MOUNTX(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
    }

    bind_list_free(binds);
    seccomp_release(ctx);

    FILE *learn = NULL;
    if (learn_name) {
        learn = fopen(learn_name, "a+");
        if (!learn) err(EXIT_FAILURE, "fopen");
    }

    // Inform the child that the scope unit has been created.
    CHECK_POSIX(write(pipe_in[1], &(uint8_t) { 0 }, 1), "write");
    set_non_blocking(pipe_in[1]);

    int timer_fd = -1;
    if (timeout) {
        timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        CHECK_POSIX(timer_fd, "timerfd_create");
        epoll_add(epoll_fd, timer_fd, EPOLLIN);

        struct itimerspec spec = { .it_value = { .tv_sec = timeout } };
        CHECK_POSIX(timerfd_settime(timer_fd, 0, &spec, NULL), "timerfd_settime");
    }

    int mbs_fd = -1;
    if (max_mbs > 0) {
        mbs_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        CHECK_POSIX(mbs_fd, "timerfd_create");
        epoll_add(epoll_fd, mbs_fd, EPOLLIN);

        long secs = mbs_check_every / 1000;
        struct timespec t = { .tv_sec = secs, .tv_nsec = (mbs_check_every % 1000) * 1000000 };
        struct itimerspec spec = { .it_interval = t, .it_value = t };
        CHECK_POSIX(timerfd_settime(mbs_fd, 0, &spec, NULL), "timerfd_settime");
    }

    uint8_t stdin_buffer[PIPE_BUF];
    ssize_t stdin_bytes_read = 0;
    bool trace_init = false;
    double current_mbs = 0;
    struct timespec last_time;
    CHECK_POSIX(clock_gettime(CLOCK_MONOTONIC, &last_time), "clock_gettime");

    for (;;) {
        struct epoll_event events[4];
        int n_event = epoll_wait(epoll_fd, events, 4, -1);

        if (n_event < 0) {
            if (errno == EINTR)
                continue;
            err(EXIT_FAILURE, "epoll_wait");
        }

        for (int i = 0; i < n_event; ++i) {
            struct epoll_event *evt = &events[i];

            if (evt->events & EPOLLERR) {
                close(evt->data.fd);
                continue;
            }

            if (evt->events & EPOLLIN) {
                if (evt->data.fd == mbs_fd) {
                    current_mbs = calculate_mbs(current_mbs, &last_time, max_mbs);
                    if (current_mbs >= max_mbs) {
                      warnx("MB-s cap reached!");
                      kill(pid, SIGKILL);
                      return EXIT_MB_S;
                    }
                    uint64_t value;
                    (void) read(mbs_fd, &value, 8); //we must read this value
                } else if (evt->data.fd == timer_fd) {
                    warnx("timeout triggered!");
                    kill(pid, SIGKILL);
                    return EXIT_TIMEOUT;
                } else if (evt->data.fd == sig_fd) {
                    handle_signal(sig_fd, pid, &trace_init, learn);
                } else if (evt->data.fd == pipe_out[0]) {
                    copy_to_stdstream(pipe_out[0], STDOUT_FILENO);
                } else if (evt->data.fd == pipe_err[0]) {
                    copy_to_stdstream(pipe_err[0], STDERR_FILENO);
                } else if (evt->data.fd == STDIN_FILENO) {
                    stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof stdin_buffer);
                    CHECK_POSIX(stdin_bytes_read, "read");
                    if (stdin_bytes_read == 0) {
                        CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        close(STDIN_FILENO);
                        close(pipe_in[1]);
                        continue;
                    }
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) {
                        CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                    "epoll_ctl");
                        continue;
                    }
                    stdin_bytes_read = 0;
                    continue;
                }
            }

            // the child process is ready for more input
            if (evt->events & EPOLLOUT && evt->data.fd == pipe_in[1]) {
                // deal with previously buffered data
                if (stdin_bytes_read > 0) {
                    ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
                    if (check_eagain(bytes_written, "write")) continue;
                    stdin_bytes_read = 0;

                    if (!stdin_non_epoll) {
                        epoll_add(epoll_fd, STDIN_FILENO, EPOLLIN); // accept more data
                    }
                }

                if (stdin_non_epoll) {
                    // drain stdin until a write would block
                    for (;;) {
                        stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof stdin_buffer);
                        CHECK_POSIX(stdin_bytes_read, "read");
                        ssize_t bytes_written = write(pipe_in[1], stdin_buffer,
                                                      (size_t)stdin_bytes_read);
                        if (check_eagain(bytes_written, "write")) break;

                        if (stdin_bytes_read < (ssize_t)sizeof stdin_buffer) {
                            close(STDIN_FILENO);
                            close(pipe_in[1]);
                            break;
                        }
                    }
                    continue;
                }
            }

            if (evt->events & EPOLLHUP) {
                if (evt->data.fd == STDIN_FILENO) {
                    close(pipe_in[1]);
                    CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL),
                                "epoll_ctl");
                }
                close(evt->data.fd);
            }
        }
    }
}
