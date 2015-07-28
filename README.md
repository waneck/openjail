Openjail is a secure application sandbox built with modern Linux sandboxing features, 
built on top of `playpen`

# Features

* The application is contained inside a read-only root directory with `chroot`.
* A mount namespace is leveraged to provide writable /tmp, /dev/tmp and home
  directories as in-memory (tmpfs) filesystems. Since these mounts are private,
  any number of Openjail instances can share the same root.
* The memory of all contained processes is limited via the scope unit's memory
  control group. The memory control group will include usage of the private
  tmpfs mounts towards the total.
* System call whitelisting forbids all but the `execve` call by default.
* Device whitelisting prevents reading, writing or creating any devices by default.
* The initial process and any forked children can be reliably killed.
* An optional timeout can take care of automatically killing the contained processes.
* An optional MB-s measure can be added so resources can be capped based on how much
  memory and time they occupy.
* rlimit can be used to add further restrictions to the sandbox.
* A process namespace hides all external processes from the sandbox.
* A network namespace provides a private loopback and no external interfaces.
* The system's hostname and IPC resources are hidden from the sandbox via
  namespaces.
* No need of root permissions to run (if kernel supports `CLONE_NEWUSER`)

# Example

    # create a chroot
    mkdir sandbox
    # on debian/ubuntu, use debootstrap instead
    pacstrap -cd sandbox

    # use the `trace` program to create a system call whitelist
    trace whitelist ls -l /

    # run the sandbox, enforcing the learned system call whitelist
    openjail sandbox -S whitelist -- ls -l /

# Dependencies

* Linux 3.8 or later
* [libseccomp](https://github.com/seccomp/libseccomp) 2.1.1 or later
