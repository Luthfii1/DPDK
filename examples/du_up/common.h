#ifndef DU_UP_COMMON_
#define DU_UP_COMMON_

#include <rte_ether.h>
#include <rte_log.h>
#include <rte_kni.h>
#include <rte_meter.h>

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
#define NB_MBUF_UE_SIDE         (8192 * 12)
#define NB_MBUF_CU_SIDE         (8192 * 4)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            64

/* Ring buffer parameters */
#define MAX_RING_NAME_LEN 32
#define APP_RING_SIZE (8192)
#define PKT_ENQUEUE 64
#define PKT_DEQUEUE 1

/* TX drain every ~100us */
#define BURST_TX_DRAIN_US 100

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ * 4

/* Number of RX ring descriptors */
#define NB_RXD                  4096

/* Number of TX ring descriptors */
#define NB_TXD                  4096

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400
#define KNI_MAX_KTHREAD         32
// each KNI device name is prefixed with "vEth-"
#define MAX_KNI_NAME_LEN        (RTE_KNI_NAMESIZE - 5)

enum lcore_role {
	LCORE_NONE,
	LCORE_UE,
	LCORE_CU,
	LCORE_CU_TX,
	LCORE_CU_RX,
	LCORE_KNI,
	LCORE_MAX,
};
#define ROLE_UE 1
#define ROLE_CU 2
#define ROLE_KNI 4

enum packet_direction {
	PKT_DIR_NONE = 0,
	PKT_DIR_UPLINK,
	PKT_DIR_DOWNLINK,
	PKT_DIR_MAX,
};

struct kni_port_params {
	uint16_t port_id;
	uint16_t group_id;
	uint16_t lcore_rx;
	uint16_t lcore_tx;
	uint16_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint16_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
	char kni_device_name[MAX_KNI_NAME_LEN];
} __rte_cache_aligned;

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

struct role_conf_per_port {
	uint8_t role;
	uint16_t lcore_rx;
	uint16_t lcore_tx;
	uint16_t lcore_kni;
	struct rte_ring *rx_ring;
} __rte_cache_aligned;

struct lcore_conf {
	uint8_t is_set;
	uint8_t role;
	uint8_t nb_kni; /* Number of KNI devices */
	uint8_t nb_port;
	uint8_t rx_port; /* UE port or CU port */
	uint8_t tx_port;
	uint8_t kni_port[RTE_MAX_ETHPORTS]; /* Port ID which each KNI device attaches to */
	uint8_t ports[RTE_MAX_ETHPORTS];

} __rte_cache_aligned;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
	/* number of pkts received from NIC, and sent to KNI */
	uint64_t rx_packets;

	/* number of pkts received from NIC, but failed to send to KNI */
	uint64_t rx_dropped;

	/* number of pkts received from KNI, and sent to NIC */
	uint64_t tx_packets;

	/* number of pkts received from KNI, but failed to send to NIC */
	uint64_t tx_dropped;
};

struct ring_conf
{
	uint32_t rx_size;
	uint32_t ring_size;
	uint32_t tx_size;
};

extern struct rte_eth_conf port_conf;

/* lcore configuration array */
extern struct lcore_conf lcore_conf[APP_MAX_LCORE];

/* port configuration array */
extern struct role_conf_per_port port_role[RTE_MAX_ETHPORTS];

/* kni device parameter array */
extern struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
extern struct kni_port_params *kni_ue_port_params;
extern struct kni_port_params *kni_cu_port_params;

/* kni device statistics array */
extern struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

/* pktmbuf pools array */
// extern struct rte_mempool *pktmbuf_pools[RTE_MAX_ETHPORTS];
extern struct rte_mempool *pktmbuf_pool_ue;
extern struct rte_mempool *pktmbuf_pool_cu;

/*  */

extern rte_atomic32_t kni_stop;
extern rte_atomic32_t kni_pause[RTE_MAX_ETHPORTS];

extern uint32_t du_dl_trunk_ip, du_f1u_ip, cu_up_ip;
extern uint16_t cu_port;
extern uint8_t nb_ue_port;
extern uint8_t nb_non_gbr_port;
extern uint16_t ue_ports[RTE_MAX_ETHPORTS];

/* KNI */
// int kni_alloc(uint8_t port_id);
void init_kni(void);
int kni_free(void);
void kni_ingress(struct kni_port_params *p);
void kni_egress(struct kni_port_params *p);
int kni_ingress_send_pkt(struct kni_port_params *p, uint16_t kni_idx, struct rte_mbuf *kni_pkt);

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

#endif /* DU_UP_COMMON_ */