/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
/* the unix port wants to know that real_stat() and
 * friends exist.  So they do. And because the Linux
 * port really uses stat64 for those...
 */
int
pseudo_stat(const char *path, struct stat *buf) {
	return real___xstat(_STAT_VER, path, buf);
}

int
pseudo_lstat(const char *path, struct stat *buf) {
	return real___lxstat(_STAT_VER, path, buf);
}

int
pseudo_fstat(int fd, struct stat *buf) {
	return real___fxstat(_STAT_VER, fd, buf);
}

int
pseudo_stat64(const char *path, struct stat64 *buf) {
	return real___xstat64(_STAT_VER, path, buf);
}

int
pseudo_lstat64(const char *path, struct stat64 *buf) {
	return real___lxstat64(_STAT_VER, path, buf);
}

int
pseudo_fstat64(int fd, struct stat64 *buf) {
	return real___fxstat64(_STAT_VER, fd, buf);
}

/* similar thing happens with mknod */
int
pseudo_mknod(const char *path, mode_t mode, dev_t dev) {
	return real___xmknod(_MKNOD_VER, path, mode, &dev);
}

int
pseudo_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev) {
	return real___xmknodat(_MKNOD_VER, dirfd, path, mode, &dev);
}

int pseudo_capset(cap_user_header_t hdrp, const cap_user_data_t datap) {
	(void)hdrp;
	(void)datap;

	return 0;
}

#ifdef PSEUDO_HAVE_IO_URING_SYSCALLS
#include "pseudo_io_uring_seccomp.c"
#endif

long
syscall(long number, ...) {
	long rc = -1;
	va_list ap;

	/* Reached before real_syscall is resolved: the caller may be a malloc
	 * implementation initializing itself, and pseudo_check_wrappers()
	 * would run _libpseudo_init() -> pseudo_init_util(), which allocates.
	 * Forward the numbers pseudo never rewrites without running that path.
	 *
	 * The !real_syscall half of the guard covers a narrower window than
	 * !_libpseudo_initted alone would: _libpseudo_init() (below) sets
	 * _libpseudo_initted before it resolves real_syscall via
	 * pseudo_init_wrappers(), so an allocator whose first touch happens
	 * from inside the constructor itself - rather than before it runs -
	 * would otherwise still fall through to pseudo_enosys() below. */
	if ((!_libpseudo_initted || !real_syscall) && number != SYS_openat2
#ifdef SYS_renameat2
	    && number != SYS_renameat2
#endif
#ifdef SYS_seccomp
	    && number != SYS_seccomp
#endif
	    ) {
		if (!real_syscall)
			real_syscall = (long (*)(long, ...)) dlsym(RTLD_NEXT, "syscall");
		if (real_syscall)
			goto call_syscall;
	}

	if (!pseudo_check_wrappers() || !real_syscall) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("syscall");
		return rc;
	}

#ifdef SYS_seccomp
	/* pseudo and seccomp are incompatible as pseudo uses different syscalls
	 * so pretend to enable seccomp but really do nothing */
	if (number == SYS_seccomp) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking seccomp.\n");
		unsigned long cmd;
		va_start(ap, number);
		cmd = va_arg(ap, unsigned long);
		va_end(ap);
		if (cmd == SECCOMP_SET_MODE_FILTER) {
		    return 0;
		}
	}
#endif

        if (pseudo_disabled) {
                goto call_syscall;
        }

	/* io_uring is not handled here.  It is refused by the seccomp filter
	 * in ports/linux/pseudo_io_uring_seccomp.c, which also catches the
	 * callers that issue the syscall instruction themselves and would
	 * never reach this wrapper. */

#ifdef SYS_openat2
	/* There is a CVE patch (CVE-2025-45582) to tar 1.34 in Centos Stream which
	 * uses syscall to access openat2() and breaks builds if we don't redirect.
	 */
	if (number == SYS_openat2) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking openat2.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char * path = va_arg(ap, const char *);
		void *how = va_arg(ap, void *);
		size_t size = va_arg(ap, size_t);

		return wrap_openat2(dirfd, path, how, size);
	}
#else
#error SYS_openat2 not defined
#endif

#ifdef SYS_open_tree
	if (number == SYS_open_tree) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking open_tree.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char *path = va_arg(ap, const char*);
		unsigned int flags = va_arg(ap, unsigned int);

		return wrap_open_tree(dirfd, path, flags);
	}
#else
#error SYS_open_tree not defined
#endif

#ifdef SYS_open_tree_attr
	if (number == SYS_open_tree_attr) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking open_tree_attr.\n");
		va_start(ap, number);
		int dirfd = va_arg(ap, int);
		const char *path = va_arg(ap, const char*);
		unsigned int flags = va_arg(ap, unsigned int);
		struct mount_attr *attr = va_arg(ap, struct mount_attr*);
		size_t size = va_arg(ap, size_t);

		return wrap_open_tree_attr(dirfd, path, flags, attr, size);
	}
#else
#error SYS_open_tree_attr not defined
#endif

#ifdef SYS_renameat2
        /* Call out wrapper, expanding the variable arguments first */
	if (number == SYS_renameat2) {
		pseudo_debug(PDBGF_SYSCALL, "syscall, faking renameat2.\n");
		va_start(ap, number);
		int olddirfd = va_arg(ap, int);
		const char * oldpath = va_arg(ap, const char *);
		int newdirfd = va_arg(ap, int);
		const char * newpath = va_arg(ap, const char *);
		unsigned int flags = va_arg(ap, unsigned int);

		return wrap_renameat2(olddirfd, oldpath, newdirfd, newpath, flags);
	}
#endif

call_syscall:
	/* On Debian 11 - gcc (Debian 10.2.1-6) this results in:
	 *   error: a label can only be part of a statement and a declaration
	 *   is not a statement
	 *
	 * adding a ; here resolves this
	 */
	;

	/* gcc magic to attempt to just pass these args to syscall. we have to
	 * guess about the number of args; the docs discuss calling conventions
	 * up to 7, so let's try that?
	 */
	void *res = __builtin_apply((void (*)(void)) real_syscall, __builtin_apply_args(), sizeof(long) * 7);
	__builtin_return(res);
}

/* unused.
 */
static long wrap_syscall(long nr, va_list ap) {
	(void) nr;
	(void) ap;
	return -1;
}

int
prctl(int option, ...) {
	int rc = -1;
	va_list ap;

	/* See syscall() above: covers both the pre-constructor window and the
	 * mid-constructor one, for every option except the one prctl() itself
	 * still special-cases below. */
	if ((!_libpseudo_initted || !real_prctl)
#ifdef PR_SET_SECCOMP
	    && option != PR_SET_SECCOMP
#endif
	    ) {
		if (!real_prctl)
			real_prctl = (int (*)(int, ...)) dlsym(RTLD_NEXT, "prctl");
		if (real_prctl)
			goto call_prctl;
	}

	if (!pseudo_check_wrappers() || !real_prctl) {
		/* rc was initialized to the "failure" value */
		pseudo_enosys("prctl");
		return rc;
	}

#ifdef SECCOMP_SET_MODE_FILTER
	/* pseudo and seccomp are incompatible as pseudo uses different syscalls
	 * so pretend to enable seccomp but really do nothing */
	if (option == PR_SET_SECCOMP) {
		unsigned long cmd;
		va_start(ap, option);
		cmd = va_arg(ap, unsigned long);
		va_end(ap);
		if (cmd == SECCOMP_SET_MODE_FILTER) {
		    return 0;
		}
	}
#endif

call_prctl:
	/* On Debian 11 - gcc (Debian 10.2.1-6) this results in:
	 *   error: a label can only be part of a statement and a declaration
	 *   is not a statement
	 *
	 * adding a ; here resolves this
	 */
	;

	/* gcc magic to attempt to just pass these args to prctl. we have to
	 * guess about the number of args; the docs discuss calling conventions
	 * up to 5, so let's try that?
	 */
	void *res = __builtin_apply((void (*)(void)) real_prctl, __builtin_apply_args(), sizeof(long) * 5);
	__builtin_return(res);
}

/* unused.
 */
static int wrap_prctl(int option, va_list ap) {
	(void) option;
	(void) ap;
	return -1;
}

#undef NFTW_NAME
#undef NFTW_STAT_NAME
#undef NFTW_STAT_STRUCT
#undef NFTW_LSTAT_NAME
#define NFTW_NAME nftw64
#define NFTW_STAT_NAME stat64
#define NFTW_STAT_STRUCT stat64
#define NFTW_LSTAT_NAME lstat64
#include "../unix/guts/nftw_wrapper_base.c"
