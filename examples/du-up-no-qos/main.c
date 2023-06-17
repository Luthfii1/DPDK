#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_ip.h>
#include <rte_gtp.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>
#include <rte_meter.h>

#include "common.h"
#include "cfg_file.h"
#include "ue_context.h"
#include "proto_hdr.h"
#include "arp_table.h"

#define MAX_POOL_NAME_LEN 32
#define CMD_LINE_OPT_CFG_FILE "cfg-file"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CFG_FILE_NUM,
};

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	;

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CFG_FILE, 1, 0, CMD_LINE_OPT_CFG_FILE_NUM},
	{NULL, 0, 0, 0}
};

/* Port mask */
static uint32_t port_mask = 0xf;

/* Mempool for mbufs */
// struct rte_mempool * pktmbuf_pool = NULL;

static volatile bool force_quit;
rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
rte_atomic32_t kni_pause[RTE_MAX_ETHPORTS];

/* Default setting of port */
struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static struct ring_conf ring_conf = {
	.rx_size   = NB_RXD,
	.ring_size = APP_RING_SIZE,
	.tx_size   = NB_TXD,
};

// static struct burst_conf burst_conf = {
// 	.rx_burst    = MAX_PKT_RX_BURST,
// 	.ring_burst  = PKT_DEQUEUE,
// 	.qos_dequeue = PKT_DEQUEUE,
// 	.tx_burst    = MAX_PKT_TX_BURST,
// };

static uint16_t nb_rxd = NB_RXD;
static uint16_t nb_txd = NB_TXD;

/* TX buffer */
static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

// struct rte_mempool *pktmbuf_pools[RTE_MAX_ETHPORTS];
struct rte_mempool *pktmbuf_pool_ue = NULL;
struct rte_mempool *pktmbuf_pool_cu = NULL;
struct rte_mempool *pktmbuf_pools[RTE_MAX_ETHPORTS];

/* Ethernet addresses of ports */
static struct rte_ether_addr port_eth_addr[RTE_MAX_ETHPORTS];

/* Role of ports */
// static uint8_t port_role[RTE_MAX_ETHPORTS];
struct role_conf_per_port port_role[RTE_MAX_ETHPORTS];

struct port_stats port_statistics[RTE_MAX_ETHPORTS];
struct lcore_conf lcore_conf[APP_MAX_LCORE];

/* kni device parameter array */
struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

/* kni device statistics array */
struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

const char *cfg_profile = NULL;

uint8_t nb_ue_port = 0;
static uint8_t nb_non_gbr_flow = 0;
uint16_t ue_ports[RTE_MAX_ETHPORTS];

static struct timespec start_time;

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
	struct timespec end_time;
	double rx_bps, tx_bps;
	double duration;
	uint64_t duration_10msec;

	/* When we receive a USR1 signal, read UE Info */
	if (signum == SIGUSR1) {
		load_ue_info();
		print_ue_info();
	}
	/* print port statistics */
	else if (signum == SIGUSR2) {
		int i, j;
		uint8_t nb_qos_flow;

		struct qos_flow_params *qos_flow;
		struct ue_info *ue_info;

		for (i = 0; i < nb_ue; i++) {
			ue_info = ue_info_array[i];
			nb_qos_flow = ue_info->nb_qos_flow;

			for (j = 0; j < nb_qos_flow; j++) {
				qos_flow = ue_info->qos_flow_array[j];
				clock_gettime(CLOCK_REALTIME, &end_time);

				duration_10msec = (end_time.tv_sec - start_time.tv_sec) * 100 + (end_time.tv_nsec - start_time.tv_nsec) / 10000000;
				duration = (double) duration_10msec / 100.0;
				if (duration > 0) {
					rx_bps = ((double) qos_flow->statistics.rx_bytes * 8) / duration;
					tx_bps = ((double) qos_flow->statistics.tx_bytes * 8) / duration;
				}
				else {
					rx_bps = tx_bps = 0;
				}

				printf(
					"[UE %04X - QoS Flow %u]\n"
					"  - duration = %f\n"
					"  - rx_pkt = %lu\n"
					"  - tx_pkt = %lu\n"
					"  - rx_bytes = %lu\n"
					"  - tx_bytes = %lu\n"
					"  - rx bps = %f\n"
					"  - tx bps = %f\n",
					ue_info->rnti, qos_flow->qfi,
					duration,
					qos_flow->statistics.rx_pkt,
					qos_flow->statistics.tx_pkt,
					qos_flow->statistics.rx_bytes,
					qos_flow->statistics.tx_bytes,
					rx_bps,
					tx_bps
				);

				qos_flow->statistics.iteration = 0;
				qos_flow->statistics.rx_pkt = 0;
				qos_flow->statistics.tx_pkt = 0;
				qos_flow->statistics.rx_bytes = 0;
				qos_flow->statistics.tx_bytes = 0;
			}
		}
		clock_gettime(CLOCK_REALTIME, &start_time);
	}
	/*
	 * When we receive a RTMIN or SIGINT or SIGTERM signal,
	 * stop kni processing
	 */
	else if (signum == SIGINT || signum == SIGTERM) {
		printf("\nSIGINT/SIGTERM received. "
			"Packet processing stopping.\n");
		// rte_atomic32_inc(&kni_stop);
		force_quit = true;
		return;
    }
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret = 0;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	uint16_t port;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF)
	{
		switch (opt) {
			case 'p':
				port_mask = parse_portmask(optarg);
				if (port_mask == 0) {
					printf("invalid portmask\n");
					return -1;
				}
				break;
			case CMD_LINE_OPT_CFG_FILE_NUM:
				cfg_profile = optarg;
				break;
			default:
				return -1;
		}
	}

	return ret;
}

static void
print_lcore_config(uint16_t lcore_id)
{
	int i;
	uint8_t role = lcore_conf[lcore_id].role;

	printf("lcore %u config: \n", lcore_id);

	if (role == LCORE_DP) {
		printf("  - Role = DP\n");
	}
	else if (role == LCORE_KNI) {
		printf("  - Role = KNI\n");
	}

	printf("  - control port = [");
	for (i = 0; i < lcore_conf[lcore_id].nb_port; i++) {
		printf(" %u", lcore_conf[lcore_id].ports[i]);
	}
	printf(" ]\n");

	fflush(stdout);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t port_id;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(port_id) {
			if (force_quit)
				return;
			if ((port_mask & (1 << port_id)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(port_id, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						port_id, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", port_id,
				       link_status_text);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
kni_ingress_send_pkt(struct kni_port_params *p, uint16_t kni_idx, struct rte_mbuf *kni_pkt)
{
	unsigned num;
	uint16_t port_id;

	if (p == NULL)
		return -1;

	port_id = p->port_id;
	num = rte_kni_tx_burst(p->kni[kni_idx], &kni_pkt, 1);

	if (!num) {
		rte_pktmbuf_free(kni_pkt);
		kni_stats[port_id].rx_dropped++;
		return -1;
	}

	return 0;
}

// +--------------------------------------------------+
// + Eth | IP | UDP | DRB Info | PDCP | SDAP | UE Pkt |
// +--------------------------------------------------+
/**
 * @brief Process uplink packets from DL Trunk port (UEs)
 * 
 * @param pkt Uplink packet
 * 
 * @return 0 - success; < 0 - fail 
 */
static int
uplink_process(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_gtp_hdr *gtp_hdr;
	struct gtp_ext_info *gtp_ext_info;
	struct ran_container_type1 *nr_ran_container;
	struct drb_ind_hdr *drb_ind_hdr;
	struct sdap_hdr *sdap_hdr = NULL;
	uint8_t *u8_ptr;

	uint8_t drb_id;
	uint8_t qfi = 0;
	uint16_t pdcp_hdr_len;
	const uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type1) + 2);
	const uint16_t dl_trunk_hdr_len =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct drb_ind_hdr);
	const uint16_t f1u_outer_hdr_len =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct rte_gtp_hdr) +
		sizeof(struct gtp_ext_info) + gtp_ext_hdr_len;
	uint16_t payload_len;
	uint16_t origin_pkt_len;
	uint64_t current_tsc;
	enum rte_color pkt_color = RTE_COLOR_GREEN;
	struct drb_params *drb;
	struct qos_flow_params *qos_flow;
	struct arp_table_entry *dst_arp_entry;

	// Get original packet length (except for ethernet header)
	origin_pkt_len = pkt->pkt_len - sizeof(struct rte_ether_hdr);
	// port_statistics[pkt->port].rx_bytes += origin_pkt_len;

	// After adj
	// +---------------------------------+
	// + DRB Info | PDCP | SDAP | UE Pkt |
	// +---------------------------------+
	rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	drb_ind_hdr = rte_pktmbuf_mtod(pkt, struct drb_ind_hdr*);
	drb_id = drb_ind_hdr->drb_id;

	drb = get_drb_by_id(drb_ind_hdr->drb_id);
	if (!drb) {
		return -1;
	}

	dst_arp_entry = arp_table_get_entry(drb->f1u_ul_ip);
	if (!dst_arp_entry) {
		RTE_LOG(ERR, DU_UP, "Could not find MAC address for CU-UP IP %u\n", drb->f1u_ul_ip);
		return -1;
	}

	pkt->dynfield1[0] = drb->ue_id;

	// Retrieve SDAP Header
	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;
	u8_ptr = (uint8_t*) (drb_ind_hdr + 1);
	sdap_hdr = (struct sdap_hdr*) (u8_ptr + pdcp_hdr_len);

	// Meter
	qfi = sdap_hdr->qfi;
	for (int i = 0; i < drb->nb_qos_flow; i++) {
		if (drb->qos_flows[i].qfi == qfi) {
			qos_flow = &drb->qos_flows[i];
			break;
		}
	}
	if (qos_flow == NULL) {
		RTE_LOG(ERR, DU_UP, "Could not find QoS Flow by QFI in uplink flow\n");
		return -1;
	}

	// Remove DRB Info header
	// +----------------------+
	// + PDCP | SDAP | UE Pkt |
	// +----------------------+
	rte_pktmbuf_adj(pkt, sizeof(struct drb_ind_hdr));
	
#ifndef PING_TEST
	// Encapsulate F1-U header
	// +----------------------------------------------------+
	// + Eth | IP | UDP | GTP | NRUP | PDCP | SDAP | UE Pkt |
	// +----------------------------------------------------+
	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(pkt, f1u_outer_hdr_len);
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
	udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
	gtp_hdr = (struct rte_gtp_hdr*) (udp_hdr + 1);
	gtp_ext_info = (struct gtp_ext_info*) (gtp_hdr + 1);
	u8_ptr = (uint8_t*) (gtp_ext_info + 1); 
	nr_ran_container = (struct ran_container_type1*) (u8_ptr + 1);
	// Set payload length
	payload_len = pkt->pkt_len;

	// Ethernet
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&port_eth_addr[drb->ue->port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&dst_arp_entry->mac_addr, &eth_hdr->d_addr);

	// IPv4
	payload_len -= sizeof(struct rte_ether_hdr);
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->total_length = rte_cpu_to_be_16(payload_len);
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IP_PROTO_UDP;
	ipv4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	ipv4_hdr->src_addr = drb->f1u_dl_ip;
	ipv4_hdr->dst_addr = drb->f1u_ul_ip;
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

	// UDP
	payload_len -= sizeof(struct rte_ipv4_hdr);
	udp_hdr->src_port = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
	udp_hdr->dst_port = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
	udp_hdr->dgram_len = rte_cpu_to_be_16(payload_len);
	
	// GTP header
	payload_len -= sizeof(struct rte_udp_hdr) + 8;
	gtp_hdr->gtp_hdr_info = (1 << 5) | (1 << 4) | (1 << 2);
	gtp_hdr->msg_type = GTP_MSG_TYPE_G_PDU;
	gtp_hdr->plen = rte_cpu_to_be_16(payload_len);
	gtp_hdr->teid = rte_cpu_to_be_32(drb->f1u_ul_teid);

	// GTP Extension header Information
	gtp_ext_info->seq_num = 0;
	gtp_ext_info->n_pdu = 0;
	gtp_ext_info->next_ext_hdr_type = GTP_EXT_HDR_TYPE_NR_RAN_CONTAINER;

	// GTP Extension header length
	*u8_ptr = gtp_ext_hdr_len >> 2;
	// NR RAN Container (PDU Type 1)
	memset(nr_ran_container, 0, sizeof(*nr_ran_container));
	nr_ran_container->pdu_type = 1;
	nr_ran_container->desired_buffer_size = rte_cpu_to_be_32(3000000);
	// Next GTP Extension header type
	u8_ptr = u8_ptr + (gtp_ext_hdr_len - 1);
	*u8_ptr = 0;

	udp_hdr->dgram_cksum = 0;
	udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
#else
	const uint16_t ping_test_hdr_len = sizeof(struct rte_ether_hdr);

	// Remove PDCP and SDAP headers
	// +----------------------+
	// + PDCP | SDAP | UE Pkt |
	// +----------------------+
	rte_pktmbuf_adj(pkt, pdcp_hdr_len + sizeof(struct sdap_hdr));

	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(pkt, ping_test_hdr_len);

	// Ethernet
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&port_eth_addr[drb->ue->port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&dst_arp_entry->mac_addr, &eth_hdr->d_addr);
#endif /* PING TEST */

	qos_flow->statistics.rx_bytes += origin_pkt_len;
	qos_flow->statistics.rx_pkt++;

	qos_flow->statistics.tx_bytes += pkt->pkt_len - sizeof(struct rte_ether_hdr);

	return 0;
}

// +----------------------------------------------------+
// + Eth | IP | UDP | GTP | NRUP | PDCP | SDAP | UE Pkt |
// +----------------------------------------------------+
/**
 * @brief Process downlink packets from CU-UP
 * 
 * @param pkt Downlink packet
 * 
 * @return 0 - success; < 0 - fail 
 */
static int
downlink_process(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_gtp_hdr *gtp_hdr;
	struct drb_ind_hdr* drb_ind_hdr;
	struct sdap_hdr *sdap_hdr = NULL;
	struct ran_container_type1 *nr_ran_container;
	uint8_t *u8_ptr;
	uint64_t current_tsc;

	const struct drb_params *drb = NULL;
	const struct qos_flow_params *qos_flow = NULL;
	const struct arp_table_entry *arp_entry;

	// uint8_t drb_id = 0;
	uint8_t qfi = 0;
	uint16_t tx_port;
	uint32_t dl_teid;
	uint32_t ue_trunk_ip;
	uint16_t pdcp_hdr_len;
	uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type0) + 2);
	const uint16_t dl_trunk_hdr_len =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct drb_ind_hdr);
	uint16_t payload_len;
	uint16_t origin_pkt_len;
	enum rte_color pkt_color = RTE_COLOR_GREEN;

	// Get original packet length (except for ethernet header)
	origin_pkt_len = pkt->pkt_len - sizeof(struct rte_ether_hdr);
	
	// After adj
	// +--------------------------------------------------+
	// | GTP | GTP EXT INFO | NRUP | PDCP | SDAP | UE Pkt |
	// +--------------------------------------------------+
#ifndef PING_TEST
	gtp_hdr = (struct rte_gtp_hdr*) rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	dl_teid = rte_be_to_cpu_32(gtp_hdr->teid);

	u8_ptr = (uint8_t*) (gtp_hdr + 1) + sizeof(struct gtp_ext_info);
	// Get NR-RAN-Container header length
	gtp_ext_hdr_len = (*u8_ptr) << 2;

	drb = get_drb_by_dl_teid(dl_teid);
	if (!drb) {
		RTE_LOG(ERR, DU_UP, "Could not find DRB by DL TEID\n");
		return -1;
	}

	// Retrieve SDAP Header
	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;
	u8_ptr = u8_ptr + gtp_ext_hdr_len + pdcp_hdr_len;
	sdap_hdr = (struct sdap_hdr*) u8_ptr;

	qfi = sdap_hdr->qfi;

	// After adj
	// +----------------------+
	// + PDCP | SDAP | UE Pkt |
	// +----------------------+
	rte_pktmbuf_adj(pkt, sizeof(struct rte_gtp_hdr) + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len);
#else
	const uint32_t gbr_ue_ip = 171704321; // 10.60.0.1
	const uint32_t ngbr_udp_ue_ip = 171704322; // 10.60.0.2
	const uint32_t ngbr_tcp_ue_ip = 171704323; // 10.60.0.3
	uint32_t dst_ip;
	ipv4_hdr = (struct rte_ipv4_hdr*) rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));
	dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

	if (dst_ip == gbr_ue_ip)
		drb = get_drb_by_id(1);
	else if (dst_ip == ngbr_udp_ue_ip)
		drb = get_drb_by_id(2);
	else if (dst_ip == ngbr_tcp_ue_ip)
		drb = get_drb_by_id(3);
	else
		return -1;
#endif

	ue_trunk_ip = drb->ue->ue_trunk_ip;
	// Retrieve target UE port
	arp_entry = arp_table_get_entry(ue_trunk_ip);
	if (!arp_entry) {
		RTE_LOG(ERR, DU_UP, "Could not find UE Trunk MAC\n");
		return -1;
	}
	tx_port = arp_entry->port;

	// After DL Trunk Encapsulation
	// +--------------------------------------------------+
	// + Eth | IP | UDP | DRB Info | PDCP | SDAP | UE Pkt |
	// +--------------------------------------------------+
#ifndef PING_TEST
	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(pkt, dl_trunk_hdr_len);
#else
	uint16_t ping_test_dl_hdr_len = dl_trunk_hdr_len + sizeof(struct pdcp_hdr_sn_18) + sizeof(struct sdap_hdr);
	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(pkt, ping_test_dl_hdr_len);
#endif
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
	udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
	drb_ind_hdr = (struct drb_ind_hdr*) (udp_hdr + 1);
#ifdef PING_TEST
	struct pdcp_hdr_sn_18 *pdcp_hdr = (struct pdcp_hdr_sn_18*) (drb_ind_hdr + 1);
	sdap_hdr = (struct sdap_hdr*) (pdcp_hdr + 1);
#endif
	payload_len = pkt->pkt_len;

	// Ethernet
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&port_eth_addr[tx_port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&arp_entry->mac_addr, &eth_hdr->d_addr);

	// IPv4
	payload_len -= sizeof(struct rte_ether_hdr);
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->total_length = rte_cpu_to_be_16(payload_len);
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IP_PROTO_UDP;
	ipv4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	ipv4_hdr->src_addr = drb->ue->du_trunk_ip;
	ipv4_hdr->dst_addr = ue_trunk_ip;
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

	// UDP
	payload_len -= sizeof(struct rte_ipv4_hdr);
	udp_hdr->src_port = rte_cpu_to_be_16(UDP_PORT_UE5G);
	udp_hdr->dst_port = rte_cpu_to_be_16(UDP_PORT_UE5G);
	udp_hdr->dgram_len = rte_cpu_to_be_16(payload_len);
	udp_hdr->dgram_cksum = 0;

	// DRB Info
	drb_ind_hdr->sdap_hdr_presence = true;
	drb_ind_hdr->R = 0;
	drb_ind_hdr->drb_id = drb->drb_id;

#ifdef PING_TEST
	// PDCP
	pdcp_hdr->DC = 1;
	pdcp_hdr->reserved = 0;
	pdcp_hdr->pdcp_sn_first_2_bits = 0;
	pdcp_hdr->pdcp_sn_last_16_bits = rte_cpu_to_be_16(1);

	// SDAP
	sdap_hdr->DC = 1;
	sdap_hdr->reserved = 0;
	sdap_hdr->qfi = 9;
#endif

	return 0;
}

static void
dp_main_loop(unsigned lcore_id)
{
	uint16_t i, j, num;
	uint16_t nb_rx;
	uint16_t nb_ul_tx, nb_ul_tx_res;
	uint16_t nb_dl_tx, nb_dl_tx_res;
	uint8_t idx, port_id, nb_dp_port;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *ul_pkts_tx[PKT_BURST_SZ];
	struct rte_mbuf *dl_pkts_tx[PKT_BURST_SZ];
	struct rte_mbuf *m;

	uint16_t ether_type;
	uint16_t src_port, dst_port;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_arp_hdr *arp_hdr;

	int32_t f_pause;
	enum packet_direction pkt_dir;
	struct lcore_conf *conf = &lcore_conf[lcore_id];
	struct kni_port_params *kni_port_param;
	struct kni_port_params *kni_params;

	nb_dp_port = conf->nb_port;

	while (!force_quit) {
		for (idx = 0; idx < nb_dp_port; idx++) {
			port_id = conf->ports[idx];
			kni_params = kni_port_params_array[port_id];

			f_pause = rte_atomic32_read(&kni_pause[kni_params->group_id]);

			if (unlikely(f_pause)) {
				continue;
			}

			nb_ul_tx = 0;
			nb_dl_tx = 0;
			nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
			if (unlikely(nb_rx > PKT_BURST_SZ)) {
				RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
				return;
			}

			for (i = 0; i < nb_rx; i++) {
				m = pkts_burst[i];
				rte_prefetch0(rte_pktmbuf_mtod(m, void*));

				eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
				ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);


				if (likely(ether_type == RTE_ETHER_TYPE_IPV4)) {
					ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
					src_port = 0;

					/* UDP packet */
					if (ipv4_hdr->next_proto_id == IP_PROTO_UDP) {
						udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
						src_port = rte_be_to_cpu_16(udp_hdr->src_port);
					}
#ifdef PING_TEST
					else if (ipv4_hdr->next_proto_id == IP_PROTO_TCP) {
						struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr*) (ipv4_hdr + 1);
						src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
						dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
					}
					else if (ipv4_hdr->next_proto_id == IP_PROTO_ICMP) {
						if (downlink_process(m) == 0)
							dl_pkts_tx[nb_dl_tx++] = m;
						else
							rte_pktmbuf_free(m);
					}
#endif

					if (src_port == UDP_PORT_UE5G) {
						RTE_LOG(DEBUG, DU_UP, "Receiving UE5G packet from port %u\n", port_id);
						/* UE5G packet */
						if (uplink_process(m) == 0)
							ul_pkts_tx[nb_ul_tx++] = m;
						else
							rte_pktmbuf_free(m);
					}
					else if (src_port == RTE_GTPU_UDP_PORT) {
						RTE_LOG(DEBUG, DU_UP, "Receiving F1-U packet from port %u\n", port_id);
						/* CU-UP packet */
						if (downlink_process(m) == 0)
							dl_pkts_tx[nb_dl_tx++] = m;
						else
							rte_pktmbuf_free(m);
					}
#ifdef PING_TEST
					else if ((src_port >= 5201 && src_port <= 5203) || (dst_port >= 5201 && dst_port <= 5203)) {
						if (downlink_process(m) == 0)
							dl_pkts_tx[nb_dl_tx++] = m;
						else
							rte_pktmbuf_free(m);
					}
#endif
					/* Other IPv4 packet
					* TCP (RFSimulator) and SCTP (F1AP) are also on this condition
					*/
					else
						kni_ingress_send_pkt(kni_params, 0, m);
				}
				else if (ether_type == RTE_ETHER_TYPE_ARP) {
					RTE_LOG(DEBUG, DU_UP, "Receiving ARP packet from port %u\n", port_id);
					/* ARP packet handling */
					arp_hdr = (struct rte_arp_hdr*) (eth_hdr + 1);
					
					arp_table_insert(port_id, arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_sha);
					kni_ingress_send_pkt(kni_params, 0, m);
				}
				/* Direct free */
				else
					rte_pktmbuf_free(m);
			}

			if (nb_ul_tx) {
				nb_ul_tx_res = rte_eth_tx_burst(port_id, 0, ul_pkts_tx, nb_ul_tx);
				if (unlikely(nb_ul_tx_res < nb_ul_tx)) {
					for (i = nb_ul_tx_res; i < nb_ul_tx; i++)
						rte_pktmbuf_free(ul_pkts_tx[i]);
				}
			}

			if (nb_dl_tx) {
				nb_dl_tx_res = rte_eth_tx_burst(port_id, 0, dl_pkts_tx, nb_dl_tx);
				if (unlikely(nb_dl_tx_res < nb_dl_tx)) {
					for (i = nb_dl_tx_res; i < nb_dl_tx; i++)
						rte_pktmbuf_free(dl_pkts_tx[i]);
				}
			}
		}
    }
}

static void
kni_port_main_loop(unsigned lcore_id)
{
	int i, nb_kni;
	int32_t f_pause;
	uint16_t port_id;
	struct lcore_conf *conf = &lcore_conf[lcore_id];
	struct kni_port_params *kni_params;

	nb_kni = conf->nb_port;

	while (!force_quit) {
		for (i = 0; i < nb_kni; i++) {
			port_id = conf->ports[i];
			kni_params = kni_port_params_array[port_id];

			f_pause = rte_atomic32_read(&kni_pause[kni_params->group_id]);
			if (likely(!f_pause)) {
				kni_egress(kni_params);
			}
		}
	}
}

static int
main_loop(__rte_unused void *arg)
{
	unsigned lcore_id;
	uint8_t role, port_id;

	lcore_id = rte_lcore_id();
	role = lcore_conf[lcore_id].role;

	if (role == LCORE_DP) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for Data Plane\n", lcore_id);
		dp_main_loop(lcore_id);
	}
	else if (role == LCORE_KNI) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for transmitting packets from KNI port\n", lcore_id);
		kni_port_main_loop(lcore_id);
	}
	else {
		RTE_LOG(INFO, DU_UP, "lcore %u has nothing to do\n", lcore_id);
	}

    return 0;
}

static void
port_init()
{
	int ret;
	uint8_t i, port_id;
	uint16_t lcore_rx_id;
	uint32_t lcore_socket_id;
	char ring_name[MAX_RING_NAME_LEN];
	char pool_name[MAX_POOL_NAME_LEN];
	struct rte_ring *ring;

	/* Initialize each port */
	for (i = 0; i < nb_ue_port; i++) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_mempool *pktmbuf_pool;

		port_id = ue_ports[i];

		if ((port_mask & (1 << port_id)) == 0) {
			printf("Skip port %u...\n", port_id);
			continue;
		}
		printf("Initializing port %u\n", port_id);
		fflush(stdout);

		/* set pktmbuf pool */
		snprintf(pool_name, MAX_POOL_NAME_LEN, "mbuf_pool_ue%u", port_id);
		pktmbuf_pools[port_id] = rte_pktmbuf_pool_create(pool_name, NB_MBUF_UE_SIDE,
			MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
		pktmbuf_pool = pktmbuf_pools[port_id];

		if (pktmbuf_pool == NULL)
			rte_exit(EXIT_FAILURE, "pktmbuf_pool for port %u is NULL\n", port_id);

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE, "Could not get device information of port %u: %s\n", port_id, strerror(-ret));
		}

		RTE_LOG(INFO, DU_UP, "Device TX offload capabilities: %lu\n", dev_info.tx_offload_capa);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		// Configure one TX/RX queue for each port
		ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err = %d, port = %u\n",
				  ret, port_id);
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err = %d, port = %u\n",
				 ret, port_id);
		ret = rte_eth_macaddr_get(port_id,
					  &port_eth_addr[port_id]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err = %d, port = %u\n",
				 ret, port_id);
		
		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		// Disable UDP Checksum
        rxq_conf.offloads &= ~DEV_RX_OFFLOAD_UDP_CKSUM;

		ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
					     rte_eth_dev_socket_id(port_id),
					     &rxq_conf,
					     pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err = %d, port = %u\n",
				  ret, port_id);

		/* init one TX queue */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		// Disable L4 Checksum
		txq_conf.offloads &= ~DEV_TX_OFFLOAD_UDP_CKSUM;

		ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err = %d, port = %u\n",
				ret, port_id);
		
		/* Initialize TX buffers */
		tx_buffer[port_id] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(PKT_BURST_SZ), 0,
				rte_eth_dev_socket_id(port_id));
		if (tx_buffer[port_id] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					port_id);

		rte_eth_tx_buffer_init(tx_buffer[port_id], PKT_BURST_SZ);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[port_id],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[port_id].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 port_id);
		
		ret = rte_eth_dev_set_ptypes(port_id, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n", port_id);
		
		/* Start device */
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err = %d, port = %u\n",
				  ret, port_id);

		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), port_id);
		
		printf("Complete initialization of port %u\n", port_id);
	}
}

static void
app_init(int argc, char **argv)
{
	int ret;
	uint8_t lcore_id;
	char pool_name[MAX_POOL_NAME_LEN];

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	/* Initialize port stats */
	memset(port_statistics, 0, sizeof(port_statistics));
	/* Initialize lcore configuration array */
	memset(lcore_conf, 0, sizeof(lcore_conf));
	/* Initialize KNI port parameters array */
	memset(kni_port_params_array, 0, sizeof(kni_port_params_array));

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid DU-UP parameters\n");

	ret = load_cfg_profile(cfg_profile);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in loading cfg file\n");

	RTE_LCORE_FOREACH(lcore_id) {
		if (lcore_conf[lcore_id].is_set) {
			print_lcore_config(lcore_id);
		}
	}

	/* Initialize ports */
	port_init();

	/* Initialize KNI subsystem */
	init_kni();
}

int main(int argc, char** argv) {
    int ret, pid;
	uint16_t nb_ports, port_id, lcore_id;
	int last_port = -1;
	unsigned i;
	void *retval;

	app_init(argc, argv);
	
	/* Check link status of all enabled ports */
	check_all_ports_link_status(port_mask);

	pid = getpid();
	RTE_LOG(INFO, DU_UP, "========================\n");
	RTE_LOG(INFO, DU_UP, "DU_UP Running\n");
	RTE_LOG(INFO, DU_UP, "kill -SIGUSR1 %d\n", pid);
	RTE_LOG(INFO, DU_UP, "    - Read UE INfo.\n");
	RTE_LOG(INFO, DU_UP, "========================\n");
	fflush(stdout);

	/* Launch main loop on each lcore */
	ret = 0;
	clock_gettime(CLOCK_REALTIME, &start_time);
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		if ((port_mask & (1 << port_id)) == 0)
			continue;
		printf("Closing port %u...", port_id);

		ret = rte_eth_dev_stop(port_id);
		if (ret != 0)
			printf("rte_eth_dev_stop: err = %d, port = %d\n",
			       ret, port_id);
		rte_eth_dev_close(port_id);

		printf(" Done\n");
	}
	kni_free();
	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}