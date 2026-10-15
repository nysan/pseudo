/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Does deny deny, and does passthrough stay out of the way?
 *
 * Deny needs a filter, a filter needs no_new_privs, and pseudo will not set
 * it on an application's behalf - so the test sets it and re-executes itself.
 * The copy which comes back has libpseudo loaded afresh with the precondition
 * met, and it is that copy which asks the kernel for a ring.  Without that the
 * test would only ever see the fallback on a machine where no_new_privs is
 * unset, which is most of them.
 *
 * Everything which is not pseudo's doing is a skip rather than a failure: a
 * kernel with no seccomp to install a filter into, an architecture pseudo has
 * no audit value for, an io_uring which has been switched off.  The one thing
 * reported as a failure is a filter being in force and io_uring working
 * anyway, because that is pseudo not keeping its word.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../ports/linux/io_uring_syscalls.h"

#define SKIP 77

#ifndef PSEUDO_HAVE_IO_URING_SYSCALLS
int
main(void)
{
	return SKIP;
}
#else

/* Old sysroots may not have them, and they are part of the kernel ABI. */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_SECCOMP
#define PR_GET_SECCOMP 21
#endif

/* io_uring_setup() needs somewhere to put what it negotiated, and the
 * argument is rejected before it is written when the call is refused, so the
 * size is all that has to be right. */
struct params {
	unsigned char opaque[120];
};

/* The two calls which need no ring, asked for with a descriptor which is not
 * one.  A refusal is decided from the syscall number alone, so the arguments
 * only have to be ones the kernel would not fault on. */
static long
io_uring_other(int which)
{
	if (which == 0)
		return syscall(SYS_io_uring_enter, -1, 0, 0, 0, NULL, 0);
	return syscall(SYS_io_uring_register, -1, 0, NULL, 0);
}

static const char *const other_name[] = {
	"io_uring_enter", "io_uring_register"
};

static int
check_deny(void)
{
	struct params p;
	long rc;
	int which;

	/* io_uring_setup() first, because its answer is what says whether the
	 * filter is in force at all. */
	memset(&p, 0, sizeof(p));
	errno = 0;
	rc = syscall(SYS_io_uring_setup, 8, &p);
	if (rc >= 0) {
		close((int) rc);
		if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2) {
			/* No filter is in force, so this kernel or this
			 * architecture could not have one installed and there
			 * is nothing here to test. */
			fprintf(stderr,
				"test-io-uring-deny: no seccomp filter in force, skipping\n");
			return SKIP;
		}
		fprintf(stderr,
			"test-io-uring-deny: io_uring_setup was not denied\n");
		return 1;
	}
	if (errno != ENOSYS) {
		/* Refused, but not by pseudo: a kernel which never had
		 * io_uring, or one with it switched off.  Deny's promise is
		 * kept either way and there is nothing to tell apart. */
		fprintf(stderr,
			"test-io-uring-deny: io_uring unavailable (errno %d), skipping\n",
			errno);
		return SKIP;
	}

	/* The filter is in force, so the other two have to answer the same
	 * way; anything else is pseudo covering only part of what it said. */
	for (which = 0; which < 2; ++which) {
		errno = 0;
		rc = io_uring_other(which);
		if (rc < 0 && errno == ENOSYS)
			continue;
		fprintf(stderr,
			"test-io-uring-deny: %s was not denied (rc %ld, errno %d)\n",
			other_name[which], rc, rc < 0 ? errno : 0);
		return 1;
	}
	return 0;
}

static int
check_passthrough(void)
{
	struct params p;
	long rc;

	memset(&p, 0, sizeof(p));
	errno = 0;
	rc = syscall(SYS_io_uring_setup, 8, &p);
	if (rc >= 0) {
		close((int) rc);
		return 0;
	}
	/* ENOSYS from a filter an ancestor installed, which cannot be removed,
	 * or from a kernel which never had io_uring; EPERM or EACCES where it
	 * has been switched off.  None of them is pseudo letting io_uring
	 * through, and none can be told from the others here. */
	fprintf(stderr,
		"test-io-uring-deny: io_uring unavailable (errno %d), skipping\n",
		errno);
	return SKIP;
}

int
main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s deny|passthrough\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "passthrough"))
		return check_passthrough();
	if (strcmp(argv[1], "deny")) {
		fprintf(stderr, "usage: %s deny|passthrough\n", argv[0]);
		return 1;
	}

	/* Deny, and this is the first of the two passes: arrange the
	 * precondition and come back through libpseudo's constructor with it
	 * in place. */
	if (argc < 3) {
		char *args[4];

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
			fprintf(stderr,
				"test-io-uring-deny: no_new_privs unavailable (errno %d), skipping\n",
				errno);
			return SKIP;
		}
		args[0] = argv[0];
		args[1] = argv[1];
		args[2] = (char *) "installed";
		args[3] = NULL;
		execv(argv[0], args);
		fprintf(stderr,
			"test-io-uring-deny: cannot re-execute %s (errno %d), skipping\n",
			argv[0], errno);
		return SKIP;
	}

	return check_deny();
}
#endif /* PSEUDO_HAVE_IO_URING_SYSCALLS */
