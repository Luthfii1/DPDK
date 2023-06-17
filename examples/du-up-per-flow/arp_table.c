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
#include "arp_table.h"

static struct arp_table_entry *arp_table[ARP_TABLE_SIZE];

// static uint16_t ip_hash(uint32_t ip)
// {
//     uint8_t i;
//     uint8_t *ptr = (uint8_t*) &ip;
//     uint16_t sum = 0;

//     for (i = 0; i < 4; i++) {
//         sum += *ptr;
//         ptr++;
//     }
//     return sum;
// }

int arp_table_insert(uint8_t port, uint32_t ip, struct rte_ether_addr mac_addr)
{
    uint32_t tb_idx = network_ip_hash(ip) & ARP_TABLE_MASK;
    struct arp_table_entry *entry;
    char buf[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip, buf, INET_ADDRSTRLEN);
    entry = arp_table_get_entry(ip);

    if (entry) {
        entry->port = port;
        entry->mac_addr = mac_addr;
        RTE_LOG(DEBUG, DU_UP, "ARP table entry for %s updates: "
            "Port = %u, MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
            buf, port,
            mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
            mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]
        );
        return 0;
    }

    entry = rte_zmalloc("ARP_TABLE_ENTRY", sizeof(struct arp_table_entry), RTE_CACHE_LINE_SIZE);
    if (entry == NULL)
        return -1;

    entry->ip = ip;
    entry->port = port;
    entry->mac_addr = mac_addr;
    entry->next = NULL;

    RTE_LOG(DEBUG, DU_UP, "Insert ARP table entry for %s: "
        "Port = %u, MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
        buf, port,
        mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
        mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]
    );

    if (arp_table[tb_idx]) {
        entry->next = arp_table[tb_idx];
    }
    arp_table[tb_idx] = entry;

    return 0;
}

struct arp_table_entry* arp_table_get_entry(uint32_t ip)
{
    uint32_t tb_idx = network_ip_hash(ip) & ARP_TABLE_MASK;
    struct arp_table_entry *entry = arp_table[tb_idx];

    while (entry) {
        if (entry->ip == ip) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}