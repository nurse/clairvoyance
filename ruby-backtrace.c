#include <ruby/ruby.h>
#include "vm_core.h"
#include "symbol.h"
#include "ruby-backtrace.h"

// iseq.h
struct iseq_line_info_entry {
    unsigned int position;
    unsigned int line_no;
};
// symbol.c 
enum {ID_ENTRY_UNIT = 512};

enum id_entry_type {
    ID_ENTRY_STR,
    ID_ENTRY_SYM,
    ID_ENTRY_SIZE
};

struct symbols {
    rb_id_serial_t last_id;
    st_table *str_sym;
    VALUE ids;
    VALUE dsymbol_fstr_hash;
};

unsigned int cfp_lineno(int pid, const VALUE *pc, struct rb_iseq_constant_body *body) {
  uintptr_t pos = pc - body->iseq_encoded;
  unsigned int size = body->line_info_size;
  if (pos != 0) {
      pos--;
  }

  //printf "size: %d\n", $size
  if (size > 0) {
      size_t sz = sizeof(struct iseq_line_info_entry) * size;
      struct iseq_line_info_entry *table = malloc(sz);
      fetch_bytes(pid, body->line_info_table, table, sz);
      unsigned int i = 1;
      while (i < size) {
	  if (table[i].position > pos) break;
	  i++;
	  if (table[i].position == pos) break;
      }
      i = table[i-1].line_no;
      free(table);
      return i;
  }
  return 0;
}

char *ptrace_rstring_ptr(int pid, VALUE v) {
    struct RString str;
    char *p;
    fetch_bytes(pid, (const void *)v, &str, sizeof(struct RString));
    if (str.basic.flags & RSTRING_NOEMBED) {
	//printf("ptr: %p %lx\n", str.as.heap.ptr, str.as.heap.len);
	p = malloc(str.as.heap.len+1);
	fetch_bytes(pid, str.as.heap.ptr, p, str.as.heap.len);
	p[str.as.heap.len] = 0;
	return p;
    } else {
	long len = ((str.basic.flags >> RSTRING_EMBED_LEN_SHIFT) & \
		(RSTRING_EMBED_LEN_MASK >> RSTRING_EMBED_LEN_SHIFT));
	// fprintf(stderr,"ary: %p %ld\n", str.as.ary, len);
	p = malloc(len+1);
	memcpy(p, str.as.ary, len);
	p[len] = 0;
    }
    return p;
}

VALUE ptrace_rarray_aref(int pid, VALUE v, long idx) {
    struct RArray ary;
    fetch_bytes(pid, (const void *)v, &ary, sizeof(struct RString));
    if (ary.basic.flags & RARRAY_EMBED_FLAG) {
	//printf("ary: %p\n", ary.as.ary);
	return ary.as.ary[idx];
    } else {
	//printf("ptr: %p %lx\n", ary.as.heap.ptr, ary.as.heap.len);
	return (VALUE)fetch(pid, ary.as.heap.ptr+idx);
    }
}

char *remote_pathobj_path(int pid, VALUE pathobj)
{
    struct RBasic basic;
    fetch_bytes(pid, (const void *)pathobj, &basic, sizeof(struct RBasic));
    if (RB_TYPE_P((VALUE)&basic, T_STRING)) {
	return ptrace_rstring_ptr(pid, pathobj);
    }
    else {
	VM_ASSERT(RB_TYPE_P((VALUE)&basic, T_ARRAY));
	return ptrace_rstring_ptr(pid, ptrace_rarray_aref(pid, pathobj, PATHOBJ_PATH));
    }
}

char *id2cstr(struct target *target, ID id) {
    rb_id_serial_t serial = rb_id_to_serial(id);
    struct symbols gsyms;
    fetch_bytes(target->pid, target->global_symbols, &gsyms, sizeof(struct symbols));
    if (serial && serial <= gsyms.last_id) {
	size_t idx = serial / ID_ENTRY_UNIT;
	VALUE ids = gsyms.ids;
	VALUE ary = ptrace_rarray_aref(target->pid, ids, idx);
	if (ary != RUBY_Qnil) {
	    idx = (serial % ID_ENTRY_UNIT) * ID_ENTRY_SIZE;
	    VALUE str = ptrace_rarray_aref(target->pid, ary, idx);
	    return ptrace_rstring_ptr(target->pid, str);
	}
    }
    return NULL;
}

const char *cfunc2path(struct target *target, void *addr) {
    struct map_entry *e = target->mappings->maps;
    while (e) {
	if (e->start <= addr && addr <= e->end) {
	   return e->path;
	}
	e = e->prev;
    }
    return NULL;
}

void show_vm_frame_type(VALUE ep0) {
    const char *magic;
    switch (ep0 & VM_FRAME_MAGIC_MASK) {
      case VM_FRAME_MAGIC_TOP:
	magic = "TOP";
	break;
      case VM_FRAME_MAGIC_METHOD:
	magic = "METHOD";
	break;
      case VM_FRAME_MAGIC_CLASS:
	magic = "CLASS";
	break;
      case VM_FRAME_MAGIC_BLOCK:
	magic = "BLOCK";
	break;
      case VM_FRAME_MAGIC_CFUNC:
	magic = "CFUNC";
	break;
      case VM_FRAME_MAGIC_IFUNC:
	magic = "IFUNC";
	break;
      case VM_FRAME_MAGIC_EVAL:
	magic = "EVAL";
	break;
      case VM_FRAME_MAGIC_RESCUE:
	magic = "RESCUE";
	break;
      case 0:
	magic = "------";
	break;
      default:
	magic = "(none)";
	break;
    }
}

rb_callable_method_entry_t *check_method_entry(int pid, rb_callable_method_entry_t *me,
	VALUE obj, bool can_be_svar) {
    if (SPECIAL_CONST_P(obj)) return NULL;

    VALUE orig = obj;
    fetch_bytes(pid, (void *)obj, me, sizeof(rb_callable_method_entry_t));
    obj = (VALUE)me;

    if (!RB_TYPE_P(obj, T_IMEMO)) {
	fprintf(stderr, "check_method_entry: unknown type: 0x%x %lx\n", TYPE(obj), orig);
	return NULL;
	abort();
    }

    switch (imemo_type(obj)) {
      case imemo_ment:
	return (rb_callable_method_entry_t *)obj;
      case imemo_cref:
	return NULL;
      case imemo_svar:
	if (can_be_svar) {
	    return check_method_entry(pid, me, ((struct vm_svar *)obj)->cref_or_me, false);
	}
	__attribute__ ((fallthrough));
      default:
	fprintf(stderr, "check_method_entry: svar should not be there: %x\n", imemo_type(obj));
	abort();
    }
    return NULL;
}

/* this cfp is local clone */
rb_callable_method_entry_t *
_rb_vm_frame_method_entry(struct target *target, rb_control_frame_t *cfp, rb_callable_method_entry_t *me)
{
    VALUE *ep = (VALUE *)cfp->ep;
    VALUE ep0 = (VALUE)fetch(target->pid, ep);
    VALUE env_me_cref;
    show_vm_frame_type(ep0);
    switch (ep0 & VM_FRAME_MAGIC_MASK) {
      case VM_FRAME_MAGIC_CFUNC:
	break;
      case 0:
      case VM_FRAME_MAGIC_METHOD:
      default:
	return NULL;
    }

    /* VM_ENV_LOCAL_P(ep) */
    while (!(ep0 & VM_ENV_FLAG_LOCAL)) {
	env_me_cref = (VALUE)fetch(target->pid, ep-2);
	//fprintf(stderr,"%d: env_me_cref: %lx\n",__LINE__,env_me_cref);
	if ((me = check_method_entry(target->pid, me, env_me_cref, false)) != NULL) return me;
	//ep = VM_ENV_PREV_EP(ep);
	ep = (VALUE *)fetch(target->pid, ep-1);
	ep0 = (VALUE)fetch(target->pid, ep);
    }

    env_me_cref = (VALUE)fetch(target->pid, ep-2);
	//fprintf(stderr,"%d: env_me_cref: %lx\n",__LINE__,env_me_cref);
    return check_method_entry(target->pid, me, env_me_cref, true);
}

void show_ruby_backtrace(struct target *target) {
    rb_thread_t thr;
    void *addr = (void *)fetch(target->pid, target->ruby_current_thread);
    printf("ruby_current_thread: %p\n", addr);
    fetch_bytes(target->pid, addr, &thr, sizeof(rb_thread_t));
    rb_control_frame_t *cfpcur = thr.ec.cfp;
    rb_control_frame_t *cfpend = (rb_control_frame_t *)(thr.ec.vm_stack + thr.ec.vm_stack_size)-1;
    //printf("cfp:%p %p\n", cfpcur,cfpend);
    while (cfpcur < cfpend) {
	rb_control_frame_t cfp;
	fetch_bytes(target->pid, cfpcur, &cfp, sizeof(rb_control_frame_t));
	//fprintf(stderr, "ep: %p vm_stack_size: %lx\n", cfp.ep, thr.ec.vm_stack_size);
	//printf("cfp.iseq: %p\n",cfp.iseq);
	if (cfp.iseq) {
	    rb_iseq_t iseq;
	    fetch_bytes(target->pid, cfp.iseq, &iseq, sizeof(rb_iseq_t));
	    //printf("iseq.body: %p\n",iseq.body);
#define RUBY_VM_IFUNC_P(ptr) imemo_type_p((VALUE)ptr, imemo_ifunc)
	    if (RUBY_VM_IFUNC_P((VALUE)&iseq)) {
		printf("%zd:<ifunc> [%p]\n", cfpend-cfpcur, iseq.body);
	    } else if (cfp.pc) {
		struct rb_iseq_constant_body body;
		fetch_bytes(target->pid, iseq.body, &body, sizeof(struct rb_iseq_constant_body));
		//printf("body.location.pathobj: %lx\n", body.location.pathobj);
		char *path = remote_pathobj_path(target->pid, body.location.pathobj);
		//printf("path: %s\n", path);
		int line = cfp_lineno(target->pid, cfp.pc, &body);
		//printf("body.location.label: %lx\n", body.location.label);
		char *label = ptrace_rstring_ptr(target->pid, body.location.label);
		printf("%zd:%s:%d:in `%s'\n", cfpend-cfpcur, path, line, label);
		free(path);
		free(label);
	    } else {
		printf("?.rb:?:in `?'\n");
	    }
	} else {
	    rb_callable_method_entry_t me;
	    if (_rb_vm_frame_method_entry(target, &cfp, &me)) {
		// if VM_FRAME_TYPE($cfp->flag) == VM_FRAME_MAGIC_CFUNC
		struct rb_method_definition_struct def;
		fetch_bytes(target->pid, me.def, &def, sizeof(struct rb_method_definition_struct));
		//printf("def.cfunc: %p\n", def.body.cfunc.func);
		const char *path = cfunc2path(target, def.body.cfunc.func);
		char *original_id_name = id2cstr(target, def.original_id);
		printf("%zd:%s [%p]:in `%s'\n", cfpend-cfpcur, path, def.body.cfunc.func, original_id_name);
		free(original_id_name);
	    } else {
		printf("unknown_frame:?\?\?:in `?\?\?'\n");
	    }
	}
	cfpcur++;
    }
}

void trace(int pid);
int main (int argc, char **argv) {

    assert(argc == 2);
    int pid = atoi(argv[1]);

    fprintf(stderr, "%d: pid: %d\n", __LINE__, pid);

    trace(pid);
    return 0;
}
