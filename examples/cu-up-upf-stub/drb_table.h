#ifndef DRB_TABLE_H_
#define DRB_TABLE_H_

#include <stdint.h>
#include "ue_context.h"

// Table size = 2 ^ 17 (131072)
#define DRB_HASH_TABLE_SIZE  (1 << 17)
#define DRB_HASK_TABLE_INDEX_MASK (DRB_HASH_TABLE_SIZE - 1)

struct drb_table_entry {
	uint32_t f1u_ul_teid;
    struct drb_params *drb_context;

    int avl_balance;
    int height;
    struct drb_table_entry *left, *right;
};

int drb_table_insert(struct drb_params *drb_context);
struct drb_table_entry* drb_table_get_entry_by_ul_teid(uint32_t ul_teid);
void print_drb_avl_tree();

#endif /* DRB_TABLE_H_ */