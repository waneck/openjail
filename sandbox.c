#include "openjail.h"
#include "helpers.h"

#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>


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

static void bind_list_apply(const char *root, struct bind_list *list) 
{
	for (; list; list = list->next) 
	{
		char *dst = join_path(root, list->dest);
		// Only use MS_REC with writable mounts to work around a kernel bug:
		// https://bugzilla.kernel.org/show_bug.cgi?id=24912
		MOUNTX(list->origin, dst, "bind", MS_BIND | (list->read_only ? 0 : MS_REC), NULL);
		if (list->read_only)
			MOUNTX(list->origin, dst, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
		free(dst);
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


int sandbox(const oj_args *args, scmp_filter_ctx ctx)
{
	// Kill this process if the parent dies. This is not a replacement for killing the sandboxed
	// processes via a control group as it is not inherited by child processes, but is more
	// robust when the sandboxed process is not allowed to fork.
	CHECK_POSIX(prctl(PR_SET_PDEATHSIG, SIGKILL));

	// Wait until the scope unit is set up before moving on. This also ensures that the parent
	// didn't die before `prctl` was called.
	uint8_t ready;
	CHECK_POSIX(read(STDIN_FILENO, &ready, sizeof ready));

	CHECK_POSIX(sethostname(args->hostname, strlen(args->hostname)));
	CHECK_POSIX(setdomainname(args->hostname, strlen(args->hostname)));

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
		char *dir = join_path(args->root, "dev/shm/tmp");
		CHECK_POSIX(mkdir(dir, S_IRWXU | S_IRWXG | S_IRWXO));
		char *tmp = join_path(args->root, "tmp");

		if (mount(dir, tmp, "bind", MS_BIND, NULL) == -1) 
		{
			if (errno != ENOENT) 
			{
				err(EXIT_FAILURE, "mounting /tmp failed");
			}
		}
		free(tmp);
		free(dir);
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
		{
			CHECK_POSIX(mkdir("/dev/shm/home", S_IRWXU | S_IRWXG |S_IRWXO));
			MOUNTX("/dev/shm/home", pw.pw_dir, "bind", MS_BIND, NULL);
		}

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
	errx(1, "Control reached after excve");
}

