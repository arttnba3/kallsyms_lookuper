#ifndef KLOOKUP_LOOKUPER_H
#define KLOOKUP_LOOKUPER_H

#include <linux/types.h>

#define KALLSYMS_NAME_LEN 512
#define KALLSYMS_MODNAME_LEN 512 

struct ksym_info {
    char name[KALLSYMS_NAME_LEN];
    char type;
    size_t addr;
    char module[KALLSYMS_MODNAME_LEN];
};

extern int kallsyms_addr_lookup(const char *name,
                                size_t *res,
                                const char **ignore_mods,
                                const char *ignore_types);

#endif // KLOOKUP_LOOKUPER_H
