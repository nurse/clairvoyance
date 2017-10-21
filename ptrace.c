#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <elf.h>
#include <string.h>
#include "ruby-backtrace.h"

void *xmalloc(size_t size) {
    void *p = malloc(size);
    if (p == NULL) {
	fprintf(stderr, "no memory");
	abort();
    }
    return p;
}

void *xrealloc(void *p, size_t size) {
    void *q = realloc(p, size);
    if (q == NULL) {
	fprintf(stderr, "no memory");
	abort();
    }
    return q;
}

void xfree(void *p) {
    free(p);
}

void stop_process(int pid) {
    assert(ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == 0);
    do {
	int status;
	waitpid(pid, &status, __WALL);
	if (WIFSTOPPED(status)) break;
    } while (1);
}

long fetch(int pid, const void *addr) {
    long r;
    errno = 0;
    r = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    assert_perror(errno);
    return r;
}

/* buf must have the capacity larger than ceil(size, 4) */
void fetch_bytes(int pid, const void *addr, void *buf, size_t size) {
    char *p = buf;
    while (size >= 8) {
	long r = fetch(pid, addr);
	memcpy(p, &r, sizeof(long));
	p += sizeof(long);
	addr += sizeof(long);
	size -= sizeof(long);
    }
    if (size > 0) {
	long r = fetch(pid, addr);
	memcpy(p, &r, size);
    }
}

void parse_maps(struct target *target);

void trace(int pid) {
    struct target target;
    target.pid = pid;

    assert(ptrace(PTRACE_SEIZE, pid, NULL, NULL) == 0);

    parse_maps(&target);

    if (!target.ruby_current_thread) {
	fprintf(stderr, "cannot find ruby_current_thread; maybe not ruby process?\n");
	exit(1);
    }
    //fprintf(stderr, "ruby_current_thread: %p\n", target.ruby_current_thread);

    stop_process(target.pid);
    show_ruby_backtrace(&target);
    assert(ptrace(PTRACE_DETACH, pid, NULL, NULL) == 0);
}
