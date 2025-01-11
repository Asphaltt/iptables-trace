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

struct nft_table {
    struct list_head		list;
    struct rhltable			chains_ht;
    struct list_head		chains;
    struct list_head		sets;
    struct list_head		objects;
    struct list_head		flowtables;
    u64				hgenerator;
    u64				handle;
    u32				use;
    u16				family:6,
                    flags:8,
                    genmask:2;
    u32				nlpid;
    char			*name;
    u16				udlen;
    u8				*udata;
    u8				validate_state;
};

struct nft_rule_blob {
    unsigned long			size;
    unsigned char			data[];
};

struct nft_chain {
    struct nft_rule_blob	*blob_gen_0;
    struct nft_rule_blob	*blob_gen_1;
    struct list_head		rules;
    struct list_head		list;
    struct rhlist_head		rhlhead;
    struct nft_table		*table;
    u64				handle;
    u32				use;
    u8				flags:5,
                    bound:1,
                    genmask:2;
    char				*name;
    u16				udlen;
    u8				*udata;

    /* Only used during control plane commit phase: */
    struct nft_rule_blob		*blob_next;
};

struct nft_pktinfo {
    struct sk_buff			*skb;
    const struct nf_hook_state	*state;
    u8				flags;
    u8				tprot;
    u16				fragoff;
    u16				thoff;
    u16				inneroff;
};

#endif // __LIBIPTABLES_H_