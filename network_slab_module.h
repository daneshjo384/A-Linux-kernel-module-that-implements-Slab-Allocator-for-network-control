#ifndef NETWORK_SLAB_MODULE_H
#define NETWORK_SLAB_MODULE_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define SLAB_CLASS_COUNT 8
#define MAX_SLAB_SIZE 8192

// ?????? ???? ?????
struct mem_block {
    struct mem_block *next;
};

// ?????? ???? ?????
struct slab_class {
    size_t item_size;
    struct mem_block *free_list;
    spinlock_t lock;
    unsigned long alloc_count;
    unsigned long free_count;
};

// ?????? ????
struct network_slab_allocator {
    char name[64];
    struct slab_class classes[SLAB_CLASS_COUNT];
    spinlock_t global_lock;
};

// ???????? ???????
extern struct network_slab_allocator *nsa;
extern int init_network_slab(void);
extern void cleanup_network_slab(void);
extern void *nsa_alloc(size_t size);
extern void nsa_free(void *ptr);
extern void nsa_print_stats(void);

// Netfilter Hook
extern unsigned int hook_func_in(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state);

#endif