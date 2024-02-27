#ifndef __VMLINUX_COMMON_H__
#define __VMLINUX_COMMON_H__

enum {
	false = 0,
	true = 1,
};

typedef _Bool bool;

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;


#endif /* __VMLINUX_COMMON_H__ */
