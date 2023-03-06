#ifndef __LIBIPTABLES_H_
#define __LIBIPTABLES_H_

#include "vmlinux.h"

#define XT_TABLE_MAXNAMELEN 32

struct xt_table_info {
	unsigned int size;
	unsigned int number;
	unsigned int initial_entries;
	unsigned int hook_entry[5];
	unsigned int underflow[5];
	unsigned int stacksize;
	void ***jumpstack;
	unsigned char entries[0];
};

struct xt_table {
	struct list_head list;
	unsigned int valid_hooks;
	struct xt_table_info *private;
	struct module *me;
	u_int8_t af;
	int priority;
	int (*table_init)(struct net *);
	const char name[32];
};

#endif // __LIBIPTABLES_H_