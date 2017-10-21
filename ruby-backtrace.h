typedef struct {
    const char *dirname;
    const char *filename;
    const char *path; /* object path */
    int line;

    uintptr_t base_addr;
    uintptr_t saddr;
    size_t size;
    const char *sname; /* function name */
} line_info_t;

typedef struct obj_info obj_info_t;
struct obj_info {
    const char *path; /* object path */
    int fd;
    void *mapped;
    size_t mapped_size;
    uintptr_t base_addr;
    obj_info_t *next;
};

struct inode_entry {
    dev_t dev;
    ino_t inode;
};

struct map_entry {
    const char *path;
    void *start;
    void *end;
    struct map_entry *prev;
};

struct mappings {
    struct inode_entry *inodes;
    size_t inosize;
    size_t inocapa;
    struct map_entry *maps;
};

struct target {
    int pid;
    struct symbols *global_symbols;
    struct mappings *mappings;
    void *ruby_current_thread;
};

void show_ruby_backtrace(struct target *target);
long fetch(int pid, const void *addr);
void fetch_bytes(int pid, const void *addr, void *buf, size_t size);
