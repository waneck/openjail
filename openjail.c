#include "openjail.h"
#include "helpers.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <pwd.h>
#include <unistd.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <time.h>

#include <seccomp.h>

#define SYSCALL_NAME_MAX 30
#define STACK_SIZE 512 * 1024
#define MOUNTX(source, target, fstype, mountflags, data) mountx(__FILE__,__LINE__,source,target,fstype,mountflags,data)

#define EXIT_TIMEOUT 3
#define EXIT_MB_S 4

__attribute__((format(printf, 4, 5))) static void my_check_posix(char *file, int line, intmax_t rc, const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	if (rc == -1)
	{
		fprintf(stderr, "%s:%d: ", file, line);
		verr(EXIT_FAILURE, fmt, args);
	}
	va_end(args);
}

__attribute__((format(printf, 2, 3))) static bool check_eagain(intmax_t rc, const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	if (rc == -1 && errno != EAGAIN) verr(EXIT_FAILURE, fmt, args);
	va_end(args);
	return rc == -1 && errno == EAGAIN;
}

static char *join_path(const char *left, const char *right) 
{
	char *dst;
	CHECK_POSIX(asprintf(&dst, "%s/%s", left, right));
	return dst;
}

static void mountx(char *file, int line, const char *source, const char *target, 
                   const char *filesystemtype, unsigned long mountflags, const void *data) 
{
	my_check_posix(file,line,mount(source, target, filesystemtype, mountflags, data),
	               "mounting %s as %s (%s) failed", source, target, filesystemtype);
}

static void bind_list_apply(const char *root, struct bind_list *list) 
{
	for (; list; list = list->next) 
	{
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
	while (list) 
	{
		struct bind_list *next = list->next;
		free(list);
		list = next;
	}
}

static void epoll_add(int epoll_fd, int fd, uint32_t events) 
{
	struct epoll_event event = { .data.fd = fd, .events = events };
	CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event));
}

static void copy_to_stdstream(int in_fd, int out_fd) 
{
	uint8_t buffer[BUFSIZ];
	ssize_t n = read(in_fd, buffer, sizeof buffer);
	if (check_eagain(n, "read")) return;
	CHECK_POSIX(write(out_fd, buffer, (size_t)n));
}

static int get_syscall_nr(const char *name) 
{
	int result = seccomp_syscall_resolve_name(name);
	if (result == __NR_SCMP_ERROR) 
	{
		errx(EXIT_FAILURE, "non-existent syscall: %s", name);
	}
	return result;
}

static void set_rlimit(int resource, long value) 
{
	struct rlimit rlim;
	if (value < 0)
		return;
	rlim.rlim_cur = (rlim_t) value;
	rlim.rlim_max = (rlim_t) value;
	CHECK_POSIX_ARGS(setrlimit((unsigned int) resource, &rlim), "set_rlimit %d", resource);
}

static void drop_capabilities() 
{
	// once we drop the privileges, we should never regain them
	// by e.g. executing a suid-root binary
	CHECK_POSIX(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	for (int i = 0; i <= 63; i++) 
	{
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
	CHECK_POSIX(clock_gettime(CLOCK_MONOTONIC, &current));
	time_t diff_ms = (current.tv_sec - last_time->tv_sec) * 1000;
	diff_ms += (current.tv_nsec - last_time->tv_nsec) / 1.0e6; // convert nanoseconds to miliseconds
	double elapsed_secs = ( (double) diff_ms ) / 1000.0;
	if (elapsed_secs < 0) err(EXIT_FAILURE, "elapsed secs < 0 : %f", elapsed_secs);
	if (elapsed_secs < 0.001) return old_mbs; // do not set current time if elapsed time is very small
	*last_time = current;

	DIR *dir = opendir("/proc");
	if (!dir) err(EXIT_FAILURE, "opendir /proc");
	struct dirent *dp;
	while( (dp = readdir(dir)) ) 
	{
		if (dp->d_name[0] < '0' || dp->d_name[0] > '9') continue;
		char *end;
		strtol(dp->d_name, &end, 10);
		if (*end == '\0') {
			// read smaps
			char *path;
			CHECK_POSIX(asprintf(&path, "/proc/%s/smaps", dp->d_name));
			FILE *stream = fopen(path, "r");
			if (NULL == stream)
				err(EXIT_FAILURE, "fopen(%s)", path);

			// unfortunately this is the only way to get the Pss
			char *line = NULL;
			size_t len;
			ssize_t read;
			while( (read = getline(&line, &len, stream)) != -1 ) 
			{
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

static void set_non_blocking(int fd) 
{
	int flags = fcntl(fd, F_GETFL, 0);
	CHECK_POSIX(flags);
	CHECK_POSIX(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

// Mark any extra file descriptors `CLOEXEC`. Only `stdin`, `stdout` and `stderr` are left open.
static void prevent_leaked_file_descriptors() 
{
	DIR *dir = opendir("/proc/self/fd");
	if (!dir) err(EXIT_FAILURE, "opendir /proc/self/fd");
	struct dirent *dp;
	while ((dp = readdir(dir))) 
	{
		char *end;
		int fd = (int)strtol(dp->d_name, &end, 10);
		if (*end == '\0' && fd > 2 && fd != dirfd(dir)) 
		{
			CHECK_POSIX(ioctl(fd, FIOCLEX));
		}
	}
	closedir(dir);
}

static void do_trace(const struct signalfd_siginfo *si, bool *trace_init, FILE *learn) 
{
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
			while (fgets(line, sizeof line, learn)) 
			{
				char *pos;
				if ((pos = strchr(line, '\n'))) *pos = '\0';
				if (!strcmp(name, line)) 
				{
					name = NULL;
					break;
				}
			}

			if (name) 
			{
				fprintf(learn, "%s\n", name);
				free(name);
			}
		}
	} else {
		CHECK_POSIX(ptrace(PTRACE_SETOPTIONS, si->ssi_pid, 0, PTRACE_O_TRACESECCOMP));
		*trace_init = true;
	}
	CHECK_POSIX(ptrace(PTRACE_CONT, si->ssi_pid, 0, inject_signal));
}

static void handle_signal(int sig_fd, pid_t child_fd,
                          bool *trace_init, FILE *learn)
{
	struct signalfd_siginfo si;
	ssize_t bytes_r = read(sig_fd, &si, sizeof(si));
	CHECK_POSIX(bytes_r);

	if (bytes_r != sizeof(si))
		errx(EXIT_FAILURE, "read the wrong amount of bytes");

	switch (si.ssi_signo) 
	{
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			kill(child_fd, SIGKILL);
			errx(EXIT_FAILURE, "interrupted, stopping early");
	}

	if (si.ssi_signo != SIGCHLD)
		errx(EXIT_FAILURE, "got an unexpected signal");

	switch (si.ssi_code) 
	{
		case CLD_EXITED:
			if (si.ssi_status) 
			{
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

static char *my_strdup(char *val)
{
	if (val)
		return strdup(val);
	return NULL;
}

static bool get_pw(const oj_args *args, struct passwd *out)
{
	if (args->is_root)
	{
		// no namespace mangling was made
		errno = 0;
		struct passwd *pw = getpwuid(getuid());
		if (!pw && errno)
			err(EXIT_FAILURE, "getpwuid");
		if (pw)
		{
			out->pw_name = my_strdup(pw->pw_name);
			out->pw_uid = pw->pw_uid;
			out->pw_gid = pw->pw_gid;
			out->pw_dir = my_strdup(pw->pw_dir);
			out->pw_shell = my_strdup(pw->pw_shell);
			return true;
		}
	}

	// if failed, use current environment info
	// this will pick up the parent namespace information
	// from the current user. If you want to override this behaviour,
	// provide a /etc/passwd with the correct information
	out->pw_name = my_strdup(getenv("USER"));
	out->pw_uid = getuid();
	out->pw_gid = getgid();
	out->pw_dir = my_strdup(getenv("HOME"));
	out->pw_shell = my_strdup(getenv("SHELL"));
	return false;
}

static void write_ns_map(char *map_name, unsigned int id)
{
	char *path;
	CHECK_POSIX(asprintf(&path, "/proc/self/%s_map", map_name));

	FILE *file = fopen(path, "w");
	if (!file) err(EXIT_FAILURE, "failed to open ns map file: %s", path);

	CHECK_POSIX(fprintf(file, "2000 %d 1\n", id));

	fclose(file);
	free(path);
}

static int sandbox(void *args);

int main(int argc, char **argv) 
{
	int status, exitstatus, flags;
	prevent_leaked_file_descriptors();

	oj_args cmd_args = { .is_root = geteuid() == 0, .orig_uid = getuid(), .orig_gid = getgid() };
	if (getuid() == 0)
	{
		errx(EXIT_FAILURE, "Running a sandbox as root is not advised. "
		                   "You may either add a setsuid bit to it and run it as an unprivileged user, "
		                   "or run as an unprivileged user, and let the sandbox use CLONE_NEWUSER");
	}
	parse_args(argc,argv,&cmd_args);

	char sandbox_stack[STACK_SIZE]; //reuse our own stack for the child

	flags = CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET;
	if (!cmd_args.is_root)
		flags |= CLONE_NEWUSER;
	pid_t pid = clone(sandbox, sandbox_stack + STACK_SIZE, flags, &cmd_args);
	CHECK_POSIX_ARGS(pid, "clone (%d)", pid);

	status = 0;
	waitpid(pid, &status, 0);
	exitstatus = WEXITSTATUS(status);
	return exitstatus;
}

int sandbox(void *my_args) 
{
	const oj_args *args = my_args;
	if (!args->is_root)
	{
		// first check if /proc/self/setgroups exists (see user_namespaces(7))
		// (this is relevant for newer kernels, which only allow setting gid mapping
		// if setgroups is set to deny)
		if (access("/proc/self/setgroups", F_OK) >= 0)
		{
			FILE *f = fopen("/proc/self/setgroups", "w");
			if (!f) err(EXIT_FAILURE, "Cannot open /proc/self/setgroups for writing");
			CHECK_POSIX(fprintf(f,"deny\n"));
			fclose(f);
		}
		// if we unshared a new user namespace,
		// we must define a uid/gid mapping
		write_ns_map("uid", args->orig_uid);
		write_ns_map("gid", args->orig_gid);
	}

	scmp_filter_ctx ctx = seccomp_init(args->learn_name ? SCMP_ACT_TRACE(0) : SCMP_ACT_KILL);
	if (!ctx) errx(EXIT_FAILURE, "seccomp_init");

	if (args->syscalls_file) 
	{
		char name[SYSCALL_NAME_MAX];
		FILE *file = fopen(args->syscalls_file, "r");
		if (!file) err(EXIT_FAILURE, "failed to open syscalls file: %s", args->syscalls_file);
		while (fgets(name, sizeof name, file)) 
		{
			char *pos;
			if ((pos = strchr(name, '\n'))) *pos = '\0';
			CHECK(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(name), 0));
		}
		fclose(file);
	}

	CHECK(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, __NR_execve, 0));

	if (args->syscalls) 
	{
		for (char *s_ptr = args->syscalls, *saveptr; ; s_ptr = NULL) 
		{
			const char *syscall = strtok_r(s_ptr, ",", &saveptr);
			if (!syscall) break;
			CHECK(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, get_syscall_nr(syscall), 0));
		}
	}

	int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	CHECK_POSIX(epoll_fd);

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	CHECK_POSIX(sigprocmask(SIG_BLOCK, &mask, NULL));

	int sig_fd = signalfd(-1, &mask, SFD_CLOEXEC);
	CHECK_POSIX(sig_fd);

	epoll_add(epoll_fd, sig_fd, EPOLLIN);

	int pipe_in[2];
	int pipe_out[2];
	int pipe_err[2];
	CHECK_POSIX(pipe(pipe_in));
	CHECK_POSIX(pipe(pipe_out));
	set_non_blocking(pipe_out[0]);
	CHECK_POSIX(pipe(pipe_err));
	set_non_blocking(pipe_err[0]);

	int rc = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO,
	                   &(struct epoll_event){ .data.fd = STDIN_FILENO, .events = EPOLLIN });
	if (rc == -1 && errno != EPERM) err(EXIT_FAILURE, "epoll_ctl");
	const bool stdin_non_epoll = rc == -1;

	epoll_add(epoll_fd, pipe_out[0], EPOLLIN);
	epoll_add(epoll_fd, pipe_err[0], EPOLLIN);
	epoll_add(epoll_fd, pipe_in[1], EPOLLET | EPOLLOUT);

	pid_t pid = fork();
	CHECK_POSIX(pid);

	if (pid == 0) 
	{
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
		CHECK_POSIX(prctl(PR_SET_PDEATHSIG, SIGKILL));

		// Wait until the scope unit is set up before moving on. This also ensures that the parent
		// didn't die before `prctl` was called.
		uint8_t ready;
		CHECK_POSIX(read(STDIN_FILENO, &ready, sizeof ready));

		CHECK_POSIX(sethostname(args->hostname, strlen(args->hostname)));

		// avoid propagating mounts to or from the parent's mount namespace
		MOUNTX(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

		// turn directory into a bind mount
		MOUNTX(args->root, args->root, "bind", MS_BIND|MS_REC, NULL);

		// re-mount as read-only
		MOUNTX(args->root, args->root, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY|MS_REC, NULL);

		if (args->mount_proc) 
		{
			char *mnt = join_path(args->root, "proc");
			MOUNTX(NULL, mnt, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
			free(mnt);
		}

		if (args->mount_dev) 
		{
			char *mnt = join_path(args->root, "dev");
			MOUNTX(NULL, mnt, "devtmpfs", MS_NOSUID|MS_NOEXEC, NULL);
			free(mnt);
		}

		if (args->mount_minimal_dev) 
		{
			char *devices[] = { "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", NULL };
			for (int i = 0; devices[i] != NULL; i++)
			{
				char *mnt = join_path(args->root, devices[i]);
				if (access(mnt, F_OK) < 0)
				{
					errx(EXIT_FAILURE,"The file '%s' was not found inside the chroot jail", mnt);
				}
				CHECK_POSIX(mount(devices[i], mnt, NULL, MS_BIND, NULL));
				free(mnt);
			}
		}

		if (args->mount_tmpfs)
		{
			char *shm = join_path(args->root, "dev/shm");
			if (mount(NULL, shm, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) 
			{
				if (errno != ENOENT) 
				{
					err(EXIT_FAILURE, "mounting /dev/shm failed");
				}
			}
			free(shm);
		}

		if (args->mount_tmpfs)
		{
			char *tmp = join_path(args->root, "tmp");
			if (mount(NULL, tmp, "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1) 
			{
				if (errno != ENOENT) 
				{
					err(EXIT_FAILURE, "mounting /tmp failed");
				}
			}
			free(tmp);
		}

		set_rlimit(RLIMIT_AS, args->rlimit_as);
		set_rlimit(RLIMIT_FSIZE, args->rlimit_fsize);
		set_rlimit(RLIMIT_NOFILE, args->rlimit_nofile);
		set_rlimit(RLIMIT_NPROC, args->rlimit_nproc);
		set_rlimit(RLIMIT_NICE, args->rlimit_nice);
		set_rlimit(RLIMIT_CPU, args->rlimit_cpu);

		bind_list_apply(args->root, args->binds);

		// preserve a reference to the target directory
		CHECK_POSIX(chdir(args->root));

		// make the working directory into the root of the mount namespace
		MOUNTX(".", "/", NULL, MS_MOVE, NULL);

		// chroot into the root of the mount namespace
		CHECK_POSIX_ARGS(chroot("."), "chroot into `%s` failed", args->root);
		CHECK_POSIX_ARGS(chdir("/"), "entering chroot `%s` failed", args->root);

		errno = 0;
		struct passwd pw;
		bool did_found = get_pw(args, &pw);

		// check if exists
		if (access(pw.pw_dir, F_OK) >= 0)
		{
			if (args->mount_tmpfs)
				MOUNTX(NULL, pw.pw_dir, "tmpfs", MS_NOSUID|MS_NODEV, NULL);

			// switch to the user's home directory as a login shell would
			CHECK_POSIX(chdir(pw.pw_dir));
		} else {
			CHECK_POSIX(chdir("/"));
		}

		drop_capabilities();
		// create a new session
		CHECK_POSIX(setsid());

		if (did_found)
			CHECK_POSIX(initgroups(pw.pw_name, pw.pw_gid));
		CHECK_POSIX(setresuid(pw.pw_uid, pw.pw_uid, pw.pw_uid));
		CHECK_POSIX(setresgid(pw.pw_gid, pw.pw_gid, pw.pw_gid));

		char path[] = "PATH=/usr/local/bin:/usr/bin:/bin";
		char *env[] = {path, NULL, NULL, NULL, NULL};
		if ((asprintf(env + 1, "HOME=%s", pw.pw_dir) < 0 ||
		     asprintf(env + 2, "USER=%s", pw.pw_name) < 0 ||
		     asprintf(env + 3, "LOGNAME=%s", pw.pw_name) < 0)) 
		{
			errx(EXIT_FAILURE, "asprintf");
		}

		if (pw.pw_name) free(pw.pw_name);
		if (pw.pw_dir) free(pw.pw_dir);
		if (pw.pw_shell) free(pw.pw_shell);

		if (args->learn_name) CHECK_POSIX(ptrace(PTRACE_TRACEME, 0, NULL, NULL));

		CHECK(seccomp_load(ctx));
		CHECK_POSIX(execvpe(args->cmd[0], args->cmd, env));
	}

	if (args->max_mbs) 
	{
		// avoid propagating mounts to or from the parent's mount namespace
		MOUNTX(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

		MOUNTX(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
	}

	bind_list_free(args->binds);
	seccomp_release(ctx);

	FILE *learn = NULL;
	if (args->learn_name) 
	{
		learn = fopen(args->learn_name, "a+");
		if (!learn) err(EXIT_FAILURE, "fopen");
	}

	// Inform the child that the scope unit has been created.
	CHECK_POSIX(write(pipe_in[1], &(uint8_t) { 0 }, 1));
	set_non_blocking(pipe_in[1]);

	int timer_fd = -1;
	if (args->timeout) 
	{
		timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
		CHECK_POSIX(timer_fd);
		epoll_add(epoll_fd, timer_fd, EPOLLIN);

		struct itimerspec spec = { .it_value = { .tv_sec = args->timeout } };
		CHECK_POSIX(timerfd_settime(timer_fd, 0, &spec, NULL));
	}

	int mbs_fd = -1;
	if (args->max_mbs > 0) 
	{
		mbs_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
		CHECK_POSIX(mbs_fd);
		epoll_add(epoll_fd, mbs_fd, EPOLLIN);

		long secs = args->mbs_check_every / 1000;
		struct timespec t = { .tv_sec = secs, .tv_nsec = (args->mbs_check_every % 1000) * 1000000 };
		struct itimerspec spec = { .it_interval = t, .it_value = t };
		CHECK_POSIX(timerfd_settime(mbs_fd, 0, &spec, NULL));
	}

	uint8_t stdin_buffer[PIPE_BUF];
	ssize_t stdin_bytes_read = 0;
	bool trace_init = false;
	double current_mbs = 0;
	struct timespec last_time;
	CHECK_POSIX(clock_gettime(CLOCK_MONOTONIC, &last_time));

	for (;;) 
	{
		struct epoll_event events[4];
		int n_event = epoll_wait(epoll_fd, events, 4, -1);

		if (n_event < 0) {
			if (errno == EINTR)
				continue;
			err(EXIT_FAILURE, "epoll_wait");
		}

		for (int i = 0; i < n_event; ++i) 
		{
			struct epoll_event *evt = &events[i];

			if (evt->events & EPOLLERR) 
			{
				close(evt->data.fd);
				continue;
			}

			if (evt->events & EPOLLIN) 
			{
				if (evt->data.fd == mbs_fd) 
				{
					current_mbs = calculate_mbs(current_mbs, &last_time, args->max_mbs);
					if (current_mbs >= args->max_mbs) 
					{
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
					CHECK_POSIX(stdin_bytes_read);
					if (stdin_bytes_read == 0) 
					{
						CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL));
						close(STDIN_FILENO);
						close(pipe_in[1]);
						continue;
					}
					ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
					if (check_eagain(bytes_written, "write")) 
					{
						CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL));
						continue;
					}
					stdin_bytes_read = 0;
					continue;
				}
			}

			// the child process is ready for more input
			if (evt->events & EPOLLOUT && evt->data.fd == pipe_in[1]) {
				// deal with previously buffered data
				if (stdin_bytes_read > 0) 
				{
					ssize_t bytes_written = write(pipe_in[1], stdin_buffer, (size_t)stdin_bytes_read);
					if (check_eagain(bytes_written, "write")) continue;
					stdin_bytes_read = 0;

					if (!stdin_non_epoll) 
					{
						epoll_add(epoll_fd, STDIN_FILENO, EPOLLIN); // accept more data
					}
				}

				if (stdin_non_epoll) 
				{
					// drain stdin until a write would block
					for (;;) 
					{
						stdin_bytes_read = read(STDIN_FILENO, stdin_buffer, sizeof stdin_buffer);
						CHECK_POSIX(stdin_bytes_read);
						ssize_t bytes_written = write(pipe_in[1], stdin_buffer,
								(size_t)stdin_bytes_read);
						if (check_eagain(bytes_written, "write")) break;

						if (stdin_bytes_read < (ssize_t)sizeof stdin_buffer) 
						{
							close(STDIN_FILENO);
							close(pipe_in[1]);
							break;
						}
					}
					continue;
				}
			}

			if (evt->events & EPOLLHUP) 
			{
				if (evt->data.fd == STDIN_FILENO) 
				{
					close(pipe_in[1]);
					CHECK_POSIX(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, STDIN_FILENO, NULL));
				}
				close(evt->data.fd);
			}
		}
	}
}
