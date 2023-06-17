#ifndef DU_UP_COMMON_
#define DU_UP_COMMON_

#include <rte_ether.h>
#include <rte_log.h>

/* Use DPDK pre-defined log type */
#define RTE_LOGTYPE_DU_UP RTE_LOGTYPE_USER1

/* MAX LCORE used in DU_UP */
#ifndef APP_MAX_LCORE
#if (RTE_MAX_LCORE > 64)
#define APP_MAX_LCORE 64
#else
#define APP_MAX_LCORE RTE_MAX_LCORE
#endif
#endif

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 4)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            64

/* Ring buffer parameters */
#define MAX_RING_NAME_LEN 32

/* TX drain every ~100us */
#define BURST_TX_DRAIN_US 100

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ * 4

/* Number of RX ring descriptors */
#define NB_RXD                  4096

/* Number of TX ring descriptors */
#define NB_TXD                  4096


enum lcore_role {
	LCORE_NONE,
	LCORE_DU,
	LCORE_DN,
	LCORE_STAT,
	LCORE_MAX,
};

/* Per-port statistics struct */
struct port_stats {
	uint8_t record;
	uint64_t iteration;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint64_t ue5g_rx;
	uint64_t ue5g_tx;
	uint64_t dropped;
} __rte_cache_aligned;

struct lcore_conf {
	uint8_t is_set;
	uint8_t role;
	uint8_t nb_port;
	uint8_t rx_port; /* UE port or CU port */
	uint8_t tx_port;
	uint8_t ports[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;

extern struct rte_eth_conf port_conf;

/* lcore configuration array */
extern struct lcore_conf lcore_conf[APP_MAX_LCORE];

/* pktmbuf pools array */
extern struct rte_mempool *pktmbuf_pools[RTE_MAX_ETHPORTS];

extern struct rte_ether_addr du_f1u_mac, dn_mac;
extern uint32_t cu_f1u_ip;
extern uint16_t du_port, dn_port;

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, DU_UP, "\t%s%s\n", name, buf);
}

static inline uint16_t
calculate_gtp_ext_hdr_len(uint16_t ext_hdr_len)
{
	return (ext_hdr_len + 0x3) & ~0x3;
}

static inline int
parse_str_to_hex_8(const char *str, uint8_t *num)
{
    unsigned long ret;
	char *next;

	*num = (uint8_t) strtoul(str, &next, 16);

    if (str[0] == '\0'|| next == NULL || *next != '\0')
		return -1;

	return 0;
}

static inline int
parse_str_to_hex_16(const char *str, uint16_t *num)
{
    unsigned long ret;
	char *next;

	*num = (uint16_t) strtoul(str, &next, 16);

    if (str[0] == '\0'|| next == NULL || *next != '\0')
		return -1;

	return 0;
}

static inline int
parse_str_to_hex_32(const char *str, uint32_t *num)
{
    unsigned long ret;
	char *next;

	*num = strtoul(str, &next, 16);

    if (str[0] == '\0'|| next == NULL || *next != '\0')
		return -1;

	return 0;
}

static inline int
parse_str_to_decimal_64(const char *str, uint64_t *num)
{
    unsigned long long ret;
	char *next;

	*num = strtoull(str, &next, 10);

    if (str[0] == '\0'|| next == NULL || *next != '\0')
		return -1;

	return 0;
}

static uint32_t network_ip_hash(uint32_t ip)
{
    return ((ip & 0x00ff0000) >> 8) | ((ip & 0xff000000) >> 24);
}

static uint32_t u32_sum_hash(uint32_t u32_val)
{
    uint8_t i;
    uint8_t *ptr = (uint8_t*) &u32_val;
    uint16_t sum = 0;

    for (i = 0; i < 4; i++) {
        sum += *ptr;
        ptr++;
    }
    return sum;
}

static inline uint32_t
jenkins_one_at_a_time_hash(const uint8_t* key, uint8_t length)
{
    uint8_t i = 0;
    uint32_t hash = 0;
    while (i != length) {
        hash += key[i++];
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    return hash;
}

#endif /* DU_UP_COMMON_ */