#include "network_slab_module.h"

static struct nf_hook_ops nfin;

static const size_t slab_sizes[SLAB_CLASS_COUNT] = {64, 128, 256, 512, 1024, 2048, 4096, 8192};

struct network_slab_allocator *nsa;

// تابع ایجاد یک slab جدید
static int create_slab_block(struct slab_class *cls) {
    void *slab = kmalloc(MAX_SLAB_SIZE, GFP_ATOMIC);
    if (!slab)
        return -ENOMEM;

    char *ptr = (char*)slab;
    for (size_t i = 0; i < (MAX_SLAB_SIZE / cls->item_size); i++) {
        struct mem_block *block = (struct mem_block*)(ptr + i * cls->item_size);
        block->next = cls->free_list;
        cls->free_list = block;
    }

    return 0;
}

// مقداردهی اولیه
int init_network_slab(void) {
    nsa = kmalloc(sizeof(struct network_slab_allocator), GFP_KERNEL);
    if (!nsa)
        return -ENOMEM;

    strncpy(nsa->name, "NetworkSlab", sizeof(nsa->name) - 1);

    spin_lock_init(&nsa->global_lock);

    for (int i = 0; i < SLAB_CLASS_COUNT; i++) {
        nsa->classes[i].item_size = slab_sizes[i];
        nsa->classes[i].free_list = NULL;
        spin_lock_init(&nsa->classes[i].lock);
        nsa->classes[i].alloc_count = 0;
        nsa->classes[i].free_count = 0;
    }

    printk(KERN_INFO "[NSA] Network Slab Allocator initialized.\n");
    return 0;
}

// تخصیص حافظه
void *nsa_alloc(size_t size) {
    int class_idx = -1;

    for (int i = 0; i < SLAB_CLASS_COUNT; i++) {
        if (size <= nsa->classes[i].item_size) {
            class_idx = i;
            break;
        }
    }

    if (class_idx == -1) {
        printk(KERN_WARNING "[NSA] Requested size %zu exceeds max slab size.\n", size);
        return NULL;
    }

    struct slab_class *cls = &nsa->classes[class_idx];
    unsigned long flags;
    spin_lock_irqsave(&cls->lock, flags);

    if (!cls->free_list) {
        if (create_slab_block(cls) != 0) {
            spin_unlock_irqrestore(&cls->lock, flags);
            return NULL;
        }
    }

    struct mem_block *block = cls->free_list;
    cls->free_list = block->next;
    cls->alloc_count++;

    spin_unlock_irqrestore(&cls->lock, flags);

    memset(block, 0, cls->item_size);
    return (void*)block;
}

// آزادسازی حافظه
void nsa_free(void *ptr) {
    if (!ptr) return;

    // پیدا کردن کلاس مربوطه — در عمل از متا داده استفاده می‌شود
    for (int i = 0; i < SLAB_CLASS_COUNT; i++) {
        struct slab_class *cls = &nsa->classes[i];
        unsigned long flags;
        spin_lock_irqsave(&cls->lock, flags);

        // فرض می‌کنیم که ptr متعلق به این کلاس است
        struct mem_block *block = (struct mem_block*)ptr;
        block->next = cls->free_list;
        cls->free_list = block;
        cls->free_count++;

        spin_unlock_irqrestore(&cls->lock, flags);
        return;
    }

    printk(KERN_WARNING "[NSA] Invalid pointer freed: %p\n", ptr);
}

// نمایش آمار
void nsa_print_stats(void) {
    printk(KERN_INFO "[NSA] Stats for %s:\n", nsa->name);
    for (int i = 0; i < SLAB_CLASS_COUNT; i++) {
        struct slab_class *cls = &nsa->classes[i];
        unsigned long leak = cls->alloc_count - cls->free_count;
        printk(KERN_INFO "Class %d: Size=%zu, Alloc=%lu, Free=%lu, Leak=%lu\n",
               i, cls->item_size, cls->alloc_count, cls->free_count, leak);
    }
}

// Netfilter Hook: پردازش بسته
unsigned int hook_func_in(void *priv,
                          struct sk_buff *skb,
                          const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // تخصیص یک بلوک برای تحلیل بسته
    char *packet_info = (char*)nsa_alloc(1024);
    if (!packet_info) return NF_DROP;

    snprintf(packet_info, 1024, "SRC: %pI4, DST: %pI4, PROTO: %d\n", &iph->saddr, &iph->daddr, iph->protocol);

    // در اینجا می‌توانید با eBPF سیاست‌های پیچیده را اعمال کنید
    // برای مثال: چک کردن یک فیلتر eBPF برای این آی‌پی

    printk(KERN_INFO "[NSA] Analyzed packet: %s", packet_info);

    // آزادسازی
    nsa_free(packet_info);

    return NF_ACCEPT;
}

// تابع بارگذاری ماژول
static int __init nsa_init(void) {
    int ret = init_network_slab();
    if (ret)
        return ret;

    nfin.hook     = hook_func_in;
    nfin.hooknum  = NF_INET_PRE_ROUTING;
    nfin.pf       = PF_INET;
    nfin.priority = NF_IP_PRI_FIRST;

    ret = nf_register_hook(&nfin);
    if (ret) {
        printk(KERN_ERR "[NSA] Failed to register Netfilter hook.\n");
        cleanup_network_slab();
        return ret;
    }

    printk(KERN_INFO "[NSA] Network Slab Allocator Module Loaded.\n");
    return 0;
}

// تابع حذف ماژول
static void __exit nsa_exit(void) {
    nf_unregister_hook(&nfin);
    nsa_print_stats();
    cleanup_network_slab();
    printk(KERN_INFO "[NSA] Network Slab Allocator Module Removed.\n");
}

void cleanup_network_slab(void) {
    if (nsa) {
        // در اینجا باید تمام slabهای تخصیص داده شده را آزاد کنیم
        // در این نمونه ساده فقط خود ساختار را آزاد می‌کنیم
        kfree(nsa);
        nsa = NULL;
    }
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Network Slab Allocator with Netfilter and eBPF Integration");
MODULE_VERSION("1.0");

module_init(nsa_init);
module_exit(nsa_exit);