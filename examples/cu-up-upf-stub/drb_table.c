#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_malloc.h>

#include "common.h"
#include "drb_table.h"

static struct drb_table_entry *drb_hash_table[DRB_HASH_TABLE_SIZE];
static struct drb_table_entry *avl_tree_root;

static inline uint32_t hash_function(uint32_t ul_teid)
{
    // return jenkins_one_at_a_time_hash((uint8_t*) &ul_teid, sizeof(ul_teid));
    return ul_teid;
}

static inline void update_avl_tree_node(struct drb_table_entry *node)
{
    int left_height = node->left ? node->left->height : 0;
    int right_height = node->right ? node->right->height : 0;

    node->height = RTE_MAX(left_height, right_height) + 1;
    node->avl_balance = left_height - right_height;
}

static struct drb_table_entry* LL_rotation(struct drb_table_entry *unbalance_root) {
    struct drb_table_entry *ub_root_left = unbalance_root->left;
    struct drb_table_entry *ub_root_left_right = ub_root_left->right;

    ub_root_left->right = unbalance_root;
    unbalance_root->left = ub_root_left_right;
    
    return ub_root_left;
}

static struct drb_table_entry* LR_rotation(struct drb_table_entry *unbalance_root) {
    struct drb_table_entry *ub_root_left = unbalance_root->left;
    struct drb_table_entry *ub_root_left_right_root = ub_root_left->right;
    struct drb_table_entry *balanced_root;

    ub_root_left->right = ub_root_left_right_root->left;
    ub_root_left_right_root->left = ub_root_left;
    unbalance_root->left = ub_root_left_right_root;

    return LL_rotation(unbalance_root);
}

static struct drb_table_entry* RR_rotation(struct drb_table_entry *unbalance_root) {
    struct drb_table_entry *ub_root_right = unbalance_root->right;
    struct drb_table_entry *ub_root_right_left = ub_root_right->left;

    ub_root_right->left = unbalance_root;
    unbalance_root->right = ub_root_right_left;
    
    return ub_root_right;
}

static struct drb_table_entry* RL_rotation(struct drb_table_entry *unbalance_root) {
    struct drb_table_entry *ub_root_right = unbalance_root->right;
    struct drb_table_entry *ub_root_right_left_root = ub_root_right->left;

    ub_root_right->left = ub_root_right_left_root->right;
    ub_root_right_left_root->right = ub_root_right;
    unbalance_root->right = ub_root_right_left_root;

    return RR_rotation(unbalance_root);
}

static void
insert_drb_to_AVL_tree(struct drb_table_entry **tree_root, struct drb_table_entry *drb_entry)
{
    struct drb_table_entry *cp = *tree_root;
    struct drb_table_entry *balanced_root = NULL;

    if (*tree_root == NULL) {
        *tree_root = drb_entry;
        return;
    }

    if (drb_entry->f1u_ul_teid < cp->f1u_ul_teid) {
        insert_drb_to_AVL_tree(&cp->left, drb_entry);
    }
    else {
        insert_drb_to_AVL_tree(&cp->right, drb_entry);
    }
    update_avl_tree_node(cp);

    // Unbalance (L/-)
    if (cp->avl_balance > 1) {
        // LL Rotation
        if (drb_entry->f1u_ul_teid < cp->left->f1u_ul_teid) {
            balanced_root = LL_rotation(cp);
        }
        // LR Rotation
        else {
            balanced_root = LR_rotation(cp);
            update_avl_tree_node(balanced_root->left);
        }
        update_avl_tree_node(balanced_root->right);
        update_avl_tree_node(balanced_root);
    }
    // Unbalance (R/-)
    else if (cp->avl_balance < -1) {
        // RR Rotation
        if (drb_entry->f1u_ul_teid > cp->right->f1u_ul_teid) {
            balanced_root = RR_rotation(cp);
        }
        // RL Rotation
        else {
            balanced_root = RL_rotation(cp);
            update_avl_tree_node(balanced_root->right);
        }
        update_avl_tree_node(balanced_root->left);
        update_avl_tree_node(balanced_root);
    }
    else
        return;

    *tree_root = balanced_root;
}

int drb_table_insert(struct drb_params *drb_context)
{
    uint32_t ul_teid = drb_context->f1u_ul_teid;
    uint32_t table_idx;
    struct drb_table_entry *entry;

    entry = drb_table_get_entry_by_ul_teid(ul_teid);

    if (entry) {
        RTE_LOG(WARNING, DU_UP, "F1U UL TEID already used for another drb %u\n", entry->drb_context->drb_id);
        return 0;
    }

    table_idx = ul_teid & DRB_HASK_TABLE_INDEX_MASK;
    entry = rte_zmalloc("DRB_TABLE_ENTRY", sizeof(struct drb_table_entry), RTE_CACHE_LINE_SIZE);
    if (entry == NULL) {
        RTE_LOG(ERR, DU_UP, "No enough for allocation of DRB hash table entry\n");
        return -1;
    }

    entry->f1u_ul_teid = ul_teid;
    entry->drb_context = drb_context;
    entry->avl_balance = 0;
    entry->height = 1;

    insert_drb_to_AVL_tree(&drb_hash_table[table_idx], entry);

    return 0;
}

struct drb_table_entry* drb_table_get_entry_by_ul_teid(uint32_t ul_teid)
{
    struct drb_table_entry *cp;
    struct drb_table_entry *entry = NULL;
    uint32_t table_idx = ul_teid & DRB_HASK_TABLE_INDEX_MASK;

    cp = drb_hash_table[table_idx];
    // cp = avl_tree_root;

    while (cp) {
        if (ul_teid == cp->f1u_ul_teid)
            break;
        else if (ul_teid < cp->f1u_ul_teid)
            cp = cp->left;
        else
            cp = cp->right;
    }

    return cp;
}

static void print_avl_tree_preorder(struct drb_table_entry *root) {
    if (root) {
        printf("[DRB %d]: DL TEID = %u, AVL balance = %d, Height = %d\n",
            root->drb_context->drb_id, root->drb_context->f1u_ul_teid, root->avl_balance, root->height);
        print_avl_tree_preorder(root->left);
        print_avl_tree_preorder(root->right);
    }
}

void print_drb_avl_tree() {
    print_avl_tree_preorder(avl_tree_root);
}