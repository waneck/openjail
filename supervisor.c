#include "openjail.h"
#include "helpers.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/wait.h>

#define SYSCALL_NAME_MAX 30

static void bind_list_free(struct bind_list *list) 
{
	while (list) 
	{
		struct bind_list *next = list->next;
		free(list);
		list = next;
	}
}

static int copy_list_apply(struct copy_list *list, const char *root)
{
	if (!list) return 0;
	// make sure we're running with the user uid / gid
	uid_t uid = getuid();
	gid_t gid = getgid();
	CHECK_POSIX(setresuid(uid, uid, uid));
	CHECK_POSIX(setresgid(gid, gid, gid));

	char *tmpfs_path = join_path(root, "dev/shm");
	struct stat tmpfs_stat;
	CHECK_POSIX(stat(tmpfs_path, &tmpfs_stat));

	int retval = 0; // 0 == success
	for (; list; list = list->next) 
	{
		char *path = join_path(root, list->origin);
		// check if file exists
		if (access(path, R_OK) != 0)
		{
			warn("--copy: file '%s' doesn't exist", path);
			goto error;
		}

		struct stat cstat;
		if (stat(path, &cstat) != 0)
		{
			warn("--copy: accessing '%s' failed", path);
			goto error;
		}

		// check if file is inside tmpfs
		if (cstat.st_dev != tmpfs_stat.st_dev)
		{
			warnx("--copy: cannot copy file '%s': it is outside of temporary mounts", list->origin);
			goto error;
		}

		// try to write to path only if it doesn't exist
		int wfd = open(list->dest, O_CREAT | O_EXCL | O_WRONLY, 0644);
		if (wfd < 0)
		{
			warn("--copy: write to file '%s' failed", list->dest);
			goto error;
		}
		int rfd = open(path, O_RDONLY);
		if (rfd < 0)
		{
			warn("--copy: read file '%s' failed", list->origin);
			close(wfd);
			goto error;
		}

		// actually copy the file
		char buf[8192];
		while(true)
		{
			ssize_t result = read(rfd, &buf[0], sizeof(buf));
			if (!result) break;
			if (result < 0) goto local_error;
			if (write(wfd, &buf[0], (size_t) result) != result) goto local_error;
			continue;

local_error:
			warn("--copy: error while copying '%s' to '%s'", list->origin, list->dest);
			close(rfd);
			close(wfd);
			goto error;
		}

		close(rfd);
		close(wfd);
		free(path);
		continue;

error:
		free(path);
		retval = 1;
		continue;
	}

	return retval;
}

static int before_exit(const oj_args *args)
{
	if (args->copies)
		return copy_list_apply(args->copies, args->root);
	return 0;
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

static void set_non_blocking(int fd) 
{
	int flags = fcntl(fd, F_GETFL, 0);
	CHECK_POSIX(flags);
	CHECK_POSIX(fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

static void handle_signal(int sig_fd, pid_t child_fd, const oj_args *args)
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

			int ret = before_exit(args);
			if (si.ssi_status)
				ret = si.ssi_status;
			exit(ret);
		case CLD_KILLED:
		case CLD_DUMPED:
			errx(EXIT_FAILURE, "application terminated abnormally with signal %d (%s)",
					si.ssi_status, strsignal(si.ssi_status));
		case CLD_TRAPPED:
		case CLD_STOPPED:
		default:
			break;
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

static void write_ns_map(char *map_name, unsigned int mapped_id, unsigned int id)
{
	char *path;
	CHECK_POSIX(asprintf(&path, "/proc/self/%s_map", map_name));

	FILE *file = fopen(path, "w");
	if (!file) err(EXIT_FAILURE, "failed to open ns map file: %s", path);

	CHECK_POSIX(fprintf(file, "%u %u 1\n", mapped_id, id));

	fclose(file);
	free(path);
}


int supervisor(void *my_args) 
{
	const oj_args *args = my_args;

	// Kill this process if the parent dies. This is not a replacement for killing the sandboxed
	// processes via a control group as it is not inherited by child processes, but is more
	// robust when the sandboxed process is not allowed to fork.
	CHECK_POSIX(prctl(PR_SET_PDEATHSIG, SIGKILL));

	// Let the main thread trace us
	if (args->learn_name)
	{
		CHECK_POSIX(ptrace(PTRACE_TRACEME, 0, NULL, NULL));
		CHECK(raise(SIGSTOP));
	}

	if (!args->is_root)
	{
		// first check if /proc/self/setgroups exists (see user_namespaces(7))
		// (this is relevant for newer kernels, which only allow setting gid mapping
		// if setgroups is set to deny)
		if (access("/proc/self/setgroups", F_OK) == 0)
		{
			FILE *f = fopen("/proc/self/setgroups", "w");
			if (!f) err(EXIT_FAILURE, "Cannot open /proc/self/setgroups for writing");
			CHECK_POSIX(fprintf(f,"deny\n"));
			fclose(f);
		}
		// if we unshared a new user namespace,
		// we must define a uid/gid mapping
		unsigned int mapped_id = 2000;
		if (args->fakeroot)
			mapped_id = 0;
		write_ns_map("uid", mapped_id, args->orig_uid);
		write_ns_map("gid", mapped_id, args->orig_gid);
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

	// avoid propagating mounts to or from the parent's mount namespace
	MOUNTX(NULL, "/", NULL, MS_PRIVATE|MS_REC, NULL);

	// before forking, we'll create a tmpfs which will still be
	// visible by the openjail process - this way we'll be able
	// to copy back the files if needed
	if (args->mount_tmpfs)
	{
		char *shm = join_path(args->root, "dev/shm");
		char *opts = NULL;
		if (args->tmpfs_size > 0)
		{
			CHECK_POSIX(asprintf(&opts, "size=%ld", args->tmpfs_size));
		}

		if (mount(NULL, shm, "tmpfs", MS_NOSUID|MS_NODEV, opts) == -1) 
		{
			err(EXIT_FAILURE, "mounting /dev/shm failed - please create this directory on the chroot target");
		}

		if (NULL != opts)
			free(opts);

		free(shm);
	}


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

		return sandbox(args, ctx);
	}

	if (args->max_mbs) 
	{
		MOUNTX(NULL, "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
	}

	bind_list_free(args->binds);
	seccomp_release(ctx);

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
					handle_signal(sig_fd, pid, args);
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
			if (evt->events & EPOLLOUT && evt->data.fd == pipe_in[1]) 
			{
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

