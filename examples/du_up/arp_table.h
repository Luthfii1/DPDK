#ifndef DU_UP_ARP_TABLE_H_
#define DU_UP_ARP_TABLE_H_

#define ARP_TABLE_SIZE  2048

struct arp_table_entry {
	uint8_t port; /* Physical port connected to machine */
	uint32_t ip; /* network byte order */
	struct rte_ether_addr mac_addr; /* MAC address mapped to IP address */

    struct arp_table_entry *next;
};

int arp_table_insert(uint8_t port, uint32_t ip, struct rte_ether_addr mac_addr);
struct arp_table_entry* arp_table_get_entry(uint32_t ip);

#endif /* DU_UP_ARP_TABLE_H_ */