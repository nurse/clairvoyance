/**********************************************************************

  addr2line.c -

  $Author$

  Copyright (C) 2010 Shinichiro Hamaji

**********************************************************************/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <linux/kdev_t.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <assert.h>


#include "ruby-backtrace.h"

void *xmalloc(size_t);
void *xrealloc(void *, size_t);
void xfree(void *);

#define SIZEOF_VOIDP __SIZEOF_POINTER__
#ifndef ElfW
# if SIZEOF_VOIDP == 8
#  define ElfW(x) Elf64##_##x
# else
#  define ElfW(x) Elf32##_##x
# endif
#endif
#ifndef ELF_ST_TYPE
# if SIZEOF_VOIDP == 8
#  define ELF_ST_TYPE ELF64_ST_TYPE
# else
#  define ELF_ST_TYPE ELF32_ST_TYPE
# endif
#endif

static void symtab_append(struct target *target, obj_info_t *obj,
	ElfW(Shdr) *symtab_shdr, ElfW(Shdr) *strtab_shdr) {
    if (!symtab_shdr || !strtab_shdr) return;
    char *strtab = obj->mapped + strtab_shdr->sh_offset;
    ElfW(Sym) *sym = (ElfW(Sym) *)(obj->mapped + symtab_shdr->sh_offset);
    ElfW(Sym) *symend = sym + (symtab_shdr->sh_size / sizeof(ElfW(Sym)));
    for (;sym < symend; sym++) {
	uintptr_t saddr = (uintptr_t)sym->st_value + obj->base_addr;
	if (ELF_ST_TYPE(sym->st_info) == STT_FUNC) {
#if 0
	    if (sym->st_size <= 0) continue;
	    line_info_t p;
	    p.sname = strtab + sym->st_name;
	    p.saddr = saddr;
	    p.size  = sym->st_size;
	    p.path  = obj->path;
	    p.base_addr = obj->base_addr;
#endif
	} else if (ELF_ST_TYPE(sym->st_info) == STT_OBJECT) {
	    const char *name = strtab + sym->st_name;
	    if (strcmp(name, "ruby_current_thread") == 0) {
		target->ruby_current_thread = (void *)saddr;
	    }
	    else if (strcmp(name, "global_symbols") == 0) {
		target->global_symbols = (void *)saddr;
	    }
	}
    }
}

static void parse_elf(struct target *target, const char *path, uintptr_t start) {
    int i;
    char *shstr;
    ElfW(Ehdr) *ehdr;
    ElfW(Shdr) *shdr, *shstr_shdr;
    //ElfW(Shdr) *debug_line_shdr = NULL, *gnu_debuglink_shdr = NULL;
    int fd;
    off_t filesize;
    char *file;
    ElfW(Shdr) *symtab_shdr = NULL, *strtab_shdr = NULL;
    ElfW(Shdr) *dynsym_shdr = NULL, *dynstr_shdr = NULL;
    obj_info_t *obj = xmalloc(sizeof(obj_info_t));
    obj->base_addr = start;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
	goto fail;
    }

    {
	struct stat st;
	if (fstat(fd, &st)) {
	    fprintf(stderr, "fstat: %s\n", strerror(errno));
	    goto fail;
	}
	filesize = st.st_size;
    }
#if SIZEOF_OFF_T > SIZEOF_SIZE_T
    if (filesize > (off_t)SIZE_MAX) {
	printf("Too large file %s\n", path);
	goto fail;
    }
#endif

    file = (char *)mmap(NULL, (size_t)filesize, PROT_READ, MAP_SHARED, fd, 0);
    if (file == MAP_FAILED) {
	fprintf(stderr, "mmap: %s\n", strerror(errno));
	goto fail;
    }

    ehdr = (ElfW(Ehdr) *)file;
    if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0) {
	/* race condition? */
	//fprintf(stderr, "non elf object: %s\n", path);
	goto fail;
    }

    //obj->fd = fd;
    obj->mapped = file;
    obj->mapped_size = (size_t)filesize;

    shdr = (ElfW(Shdr) *)(file + ehdr->e_shoff);

    shstr_shdr = shdr + ehdr->e_shstrndx;
    shstr = file + shstr_shdr->sh_offset;

    for (i = 0; i < ehdr->e_shnum; i++) {
	char *section_name = shstr + shdr[i].sh_name;
	switch (shdr[i].sh_type) {
	  case SHT_STRTAB:
	    if (!strcmp(section_name, ".strtab")) {
		strtab_shdr = shdr + i;
	    }
	    else if (!strcmp(section_name, ".dynstr")) {
		dynstr_shdr = shdr + i;
	    }
	    break;
	  case SHT_SYMTAB:
	    /* if (!strcmp(section_name, ".symtab")) */
	    symtab_shdr = shdr + i;
	    break;
	  case SHT_DYNSYM:
	    /* if (!strcmp(section_name, ".dynsym")) */
	    dynsym_shdr = shdr + i;
	    break;
#if 0
	  case SHT_PROGBITS:
	    if (!strcmp(section_name, ".debug_line")) {
		debug_line_shdr = shdr + i;
	    }
	    else if (!strcmp(section_name, ".gnu_debuglink")) {
		gnu_debuglink_shdr = shdr + i;
	    }
	    break;
#endif
	}
    }

    symtab_append(target, obj, symtab_shdr, strtab_shdr);
    symtab_append(target, obj, dynsym_shdr, dynstr_shdr);

    close(fd);
    return;
fail:
    if (fd > 0) close(fd);
    return;
}

static struct mappings *mappings_create() {
    struct mappings *m = xmalloc(sizeof(struct mappings));
    m->inosize = 0;
    m->inocapa = 32;
    m->inodes = xmalloc(sizeof(struct inode_entry) * m->inocapa);
    m->maps = NULL;
    return m;
}

static bool mappings_include(struct mappings *m, dev_t dev, unsigned long long inode) {
    struct inode_entry *p = m->inodes;
    struct inode_entry *pend = p + m->inosize;
    while (p < pend) {
	if (p->dev == dev && p->inode == inode) return true;
	p++;
    }
    return false;
}

static void mappings_append(struct mappings *m, void *start, void *end, unsigned int dev_major, unsigned int dev_minor, unsigned long long inode, const char *path) {
    if (path == NULL || path[0] != '/') return;
    {
	dev_t dev = MKDEV(dev_major, dev_minor);
	struct inode_entry *e;
	if (mappings_include(m, dev, inode)) return;
	if (m->inosize == m->inocapa) {
	    m->inodes = xrealloc(m->inodes, m->inocapa * 2);
	}
	e = &m->inodes[m->inosize++];
	e->dev = dev;
	e->inode = inode;
    }
    {
	struct map_entry *e = xmalloc(sizeof(struct map_entry));
	e->path = xmalloc(strlen(path));
	strcpy((char *)e->path, path);
	e->start = start; // assume first entry has minimum address
	e->end = end;
	e->prev = m->maps;
	m->maps = e;
    }
}

static void mappings_scan(struct target *target) {
    struct map_entry *e = target->mappings->maps;
    while (e) {
	//fprintf(stderr, "  %p-%p %s\n", e->start, e->end, e->path);
	parse_elf(target, e->path, (uintptr_t)e->start);
	e = e->prev;
    }
}

void parse_maps(struct target *target) {
    char buf[20];
    snprintf(buf, sizeof(buf), "/proc/%d/maps", target->pid);
    FILE *fp = fopen(buf, "rm");
    assert_perror(errno);

    struct mappings *maps = mappings_create();
    for (;;) {
	void *start, *end;
	char flags[32];
	unsigned int dev_major, dev_minor;
	unsigned long long file_offset, inode;
	char path[4096] = "/";
	//printf("%d: %ld\n",__LINE__,ftell(fp));
	int r = fscanf(fp, "%p-%p %31s %llx %x:%x %llu ", &start, &end, flags, &file_offset, &dev_major, &dev_minor, &inode);
	//printf("%p-%p %s -> %d %d\n",start,end,flags,r,errno);
	if (r == EOF) break;
	r = fscanf(fp, "[%*s ");
	//printf("-> %d %d\n",r,errno);
	if (r == EOF) break;
	r = fscanf(fp, "/%s ", path+1);
	//printf("%s -> %d %d\n",path,r,errno);
	if (r == EOF) break;
	if (r == 0) {
	    continue;
	}

	mappings_append(maps, start, end, dev_major, dev_minor, inode, path);

	//relative_nanosleep();
    }
    target->mappings = maps;
    mappings_scan(target);

    fclose(fp);
}
