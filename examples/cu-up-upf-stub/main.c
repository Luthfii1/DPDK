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
#include <rte_meter.h>

#include "common.h"
#include "cfg_file.h"
#include "proto_hdr.h"
#include "ue_context.h"
#include "drb_table.h"

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
rte_atomic32_t qos_flow_config_mutex = RTE_ATOMIC32_INIT(0);

/* Default setting of port */
struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = DEV_TX_OFFLOAD_IPV4_CKSUM
	},
};

static uint16_t nb_rxd = NB_RXD;
static uint16_t nb_txd = NB_TXD;

/* TX buffer */
static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];
struct rte_mempool *pktmbuf_pools[RTE_MAX_ETHPORTS];

/* Ethernet addresses of ports */
static struct rte_ether_addr port_eth_addr[RTE_MAX_ETHPORTS];

struct port_stats port_statistics[RTE_MAX_ETHPORTS];
struct lcore_conf lcore_conf[APP_MAX_LCORE];

const char *cfg_profile = NULL;

uint16_t du_port, dn_port;

struct rte_ether_addr du_f1u_mac, dn_mac;
uint32_t cu_f1u_ip;

static volatile uint16_t nb_active_qos_flow = 0;

/* Custom handling of signals to handle stats */
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
	/*
	 * When we receive a RTMIN or SIGINT or SIGTERM signal
	 */
	else if (signum == SIGINT || signum == SIGTERM) {
		printf("\nSIGINT/SIGTERM received. "
			"Packet processing stopping.\n");
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

static void
stat_collect_loop() {
	const char *stat_filename = "../qos_flow_stat.log";
	FILE *stat;
	struct ue_info *ue;
	struct qos_flow_params **qos_flow_arr, *qos_flow;
	struct qos_flow_statistics *qos_flow_stats;
	uint64_t time_second = 0;
	uint8_t print_title = 1;

	struct timespec stat_start_time, stat_end_time;
	double ul_rx_bps, dl_rx_bps;
	double duration;
	uint64_t duration_10msec;

	stat = fopen(stat_filename, "w");

	if (!stat) {
		RTE_LOG(ERR, DU_UP, "Could not create %s\n", stat_filename);
		return;
	}


	while (!force_quit) {
		if (nb_active_qos_flow == 0)
			continue;

		if (unlikely(print_title)) {
			fprintf(stat, "#RX  ");
			for (int i = 0; i < nb_ue; i++) {
				ue = runtime_ue_array[i];
				fprintf(stat, "\t%04X-%02u-UL", ue->rnti, ue->default_drb.default_qfi);
				fprintf(stat, "\t%04X-%02u-DL", ue->rnti, ue->default_drb.default_qfi);
			}
			fprintf(stat, "\n");
			print_title = 0;
			clock_gettime(CLOCK_REALTIME, &stat_start_time);
		}

		sleep(1);

		fprintf(stat, "%5lu", time_second);

		for (int i = 0; i < nb_ue; i++) {
			ue = runtime_ue_array[i];
			qos_flow_stats = &ue->default_drb.statistics;
			clock_gettime(CLOCK_REALTIME, &stat_end_time);

			duration_10msec = (stat_end_time.tv_sec - stat_start_time.tv_sec) * 100 + (stat_end_time.tv_nsec - stat_start_time.tv_nsec) / 10000000;
			duration = (double) duration_10msec / 100.0;
			if (duration > 0) {
				ul_rx_bps = ((double) qos_flow_stats->ul_rx_bytes * 8) / duration;
				dl_rx_bps = ((double) qos_flow_stats->dl_rx_bytes * 8) / duration;
			}
			else {
				ul_rx_bps = dl_rx_bps = 0;
			}

			fprintf(stat, "\t%10.2f", ul_rx_bps / 1000000000);
			fprintf(stat, "\t%10.2f", dl_rx_bps / 1000000000);

			qos_flow_stats->ul_rx_pkt = qos_flow_stats->dl_rx_pkt = 0;
			qos_flow_stats->ul_tx_pkt = qos_flow_stats->dl_tx_pkt = 0;
			qos_flow_stats->ul_rx_bytes = qos_flow_stats->dl_rx_bytes = 0;
			qos_flow_stats->ul_tx_bytes = qos_flow_stats->dl_tx_bytes = 0;
		}
		fprintf(stat, "\n");

		time_second++;
		stat_start_time = stat_end_time;
	}

	fclose(stat);
}

/**
 * @brief Process uplink packets from DU-UP
 * 
 * @param pkt Uplink packet
 * 
 * @return 0 - success; < 0 - fail 
 */
static int
uplink_process(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_gtp_hdr *gtp_hdr;
	
	uint16_t pdcp_hdr_len;
	uint32_t ul_teid;
	const uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type1) + 2);
	struct drb_params *drb;

	gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_gtp_hdr*, 
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	ul_teid = rte_be_to_cpu_32(gtp_hdr->teid);

	drb = get_drb_by_ul_teid(ul_teid);
	if (unlikely(!drb)) {
		RTE_LOG(ERR, DU_UP, "Could not find DRB for UL F1-U packet by UL TEID %08X\n", ul_teid);
		return -1;
	}

	if (unlikely(!drb->is_active)) {
		drb->is_active = true;
		nb_active_qos_flow++;
	}
	drb->statistics.ul_rx_bytes += pkt->pkt_len + 24;
	drb->statistics.ul_rx_pkt++;

	// Calculate PDCP header length
	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;

	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_adj(
		pkt, 
		sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct rte_gtp_hdr) +
		sizeof(struct gtp_ext_info) + gtp_ext_hdr_len + pdcp_hdr_len + sizeof(struct sdap_hdr)
	);

	// Ethernet
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&port_eth_addr[dn_port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&dn_mac, &eth_hdr->d_addr);

	return 0;
}

/**
 * @brief Process downlink packets from Data Network
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
	struct gtp_ext_info *gtp_ext_info;
	struct ran_container_type0 *nr_ran_container;
	struct pdcp_hdr_sn_18 *pdcp_18;
	struct pdcp_hdr_sn_12 *pdcp_12;
	struct sdap_hdr *sdap_hdr = NULL;
	
	uint8_t *u8_ptr;

	struct drb_params *drb = NULL;
	struct qos_flow_params *qos_flow = NULL;

	// uint8_t drb_id = 0;
	uint8_t qfi = 0;
	uint16_t tx_port;
	uint32_t ul_teid;
	uint16_t pdcp_hdr_len;
	uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type0) + 2);
	const uint16_t dl_f1u_hdr_len =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
		sizeof(struct rte_gtp_hdr) + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len;
	uint16_t payload_len;

	ipv4_hdr = (struct rte_ipv4_hdr*) rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));

	drb = get_drb_by_pdu_ip(ipv4_hdr->dst_addr);
	drb->statistics.dl_rx_bytes += pkt->pkt_len + 24;
	drb->statistics.dl_rx_pkt++;
	
	if (!drb) {
		RTE_LOG(ERR, DU_UP, "Could not find DRB for DL packet with IP %u\n", ipv4_hdr->dst_addr);
		return -1;
	}

	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;
	
	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(pkt, dl_f1u_hdr_len + pdcp_hdr_len + sizeof(struct sdap_hdr));
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
	udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
	gtp_hdr = (struct rte_gtp_hdr*) (udp_hdr + 1);
	gtp_ext_info = (struct gtp_ext_info*) (gtp_hdr + 1);
	u8_ptr = (uint8_t*) (gtp_ext_info + 1); 
	nr_ran_container = (struct ran_container_type0*) (u8_ptr + 1);
	// Set payload length
	payload_len = pkt->pkt_len;

	// Ethernet
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	rte_ether_addr_copy(&port_eth_addr[du_port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&du_f1u_mac, &eth_hdr->d_addr);

	// IPv4
	payload_len -= sizeof(struct rte_ether_hdr);
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->total_length = rte_cpu_to_be_16(payload_len);
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IP_PROTO_UDP;
	ipv4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	ipv4_hdr->src_addr = cu_f1u_ip;
	ipv4_hdr->dst_addr = drb->f1u_dl_ip;
	ipv4_hdr->hdr_checksum = 0;
	// ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);

	// UDP
	payload_len -= sizeof(struct rte_ipv4_hdr);
	udp_hdr->src_port = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
	udp_hdr->dst_port = rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);
	udp_hdr->dgram_len = rte_cpu_to_be_16(payload_len);
	udp_hdr->dgram_cksum = 0;

	// GTP header
	payload_len -= sizeof(struct rte_udp_hdr) + 8;
	gtp_hdr->gtp_hdr_info = (1 << 5) | (1 << 4) | (1 << 2);
	gtp_hdr->msg_type = GTP_MSG_TYPE_G_PDU;
	gtp_hdr->plen = rte_cpu_to_be_16(payload_len);
	gtp_hdr->teid = rte_cpu_to_be_32(drb->f1u_dl_teid);

	// GTP Extension header Information
	gtp_ext_info->seq_num = 0;
	gtp_ext_info->n_pdu = 0;
	gtp_ext_info->next_ext_hdr_type = GTP_EXT_HDR_TYPE_NR_RAN_CONTAINER;

	// GTP Extension header length
	*u8_ptr = gtp_ext_hdr_len >> 2;
	// NR RAN Container (PDU Type 0)
	memset(nr_ran_container, 0, sizeof(*nr_ran_container));
	nr_ran_container->pdu_type = 0;
	nr_ran_container->user_data_exist_flag = 1;
	nr_ran_container->nr_seq = drb->dl_pdcp_sn;
	// Next GTP Extension header type
	u8_ptr = u8_ptr + (gtp_ext_hdr_len - 1);
	*u8_ptr = 0;

	// PDCP
	if (drb->dl_pdcp_hdr_type == PDCP_18_BIT) {
		pdcp_18 = (struct pdcp_hdr_sn_18*) (u8_ptr + 1);
		pdcp_18->DC = 1;
		pdcp_18->pdcp_sn_first_2_bits = (drb->dl_pdcp_sn >> 16) & 0x3;
		pdcp_18->pdcp_sn_last_16_bits = rte_cpu_to_be_16((uint16_t) drb->dl_pdcp_sn);

		sdap_hdr = (struct sdap_hdr*) (pdcp_18 + 1);
	}
	else {
		pdcp_12 = (struct pdcp_hdr_sn_12*) (u8_ptr + 1);
		pdcp_12->DC = 1;
		pdcp_12->pdcp_sn_first_4_bits = (drb->dl_pdcp_sn >> 8) & 0xf;
		pdcp_12->pdcp_sn_last_8_bits = (uint8_t) (drb->dl_pdcp_sn & 0xff);

		sdap_hdr = (struct sdap_hdr*) (pdcp_12 + 1);
	}
	drb->dl_pdcp_sn++;

	// SDAP
	sdap_hdr->DC = 1;
	sdap_hdr->reserved = 0;
	sdap_hdr->qfi = drb->default_qfi;

	rte_eth_tx_buffer(tx_port, 0, tx_buffer[tx_port], pkt);

	return 0;
}


static void
du_main_loop(unsigned lcore_id)
{
	// int sent;
	uint8_t idx;
	uint16_t i, j;
	uint16_t nb_rx, nb_tx, nb_tx_res;
	uint16_t rx_port;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *ue_pkts_tx[PKT_BURST_SZ];
	struct rte_mbuf *m;

	uint16_t ether_type;
	uint16_t src_port;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_arp_hdr *arp_hdr;

	struct lcore_conf *conf = &lcore_conf[lcore_id];
	uint64_t current_tsc;

	while (!force_quit) {
		nb_tx = 0;
		nb_rx = rte_eth_rx_burst(du_port, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
			return;
		}

		if (!nb_rx)
			continue;

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

				if (src_port == RTE_GTPU_UDP_PORT) {
					RTE_LOG(DEBUG, DU_UP, "Receive UL F1-U packet from port %u\n", m->port);
					/* UE5G packet */
					if (uplink_process(m) == 0)
						ue_pkts_tx[nb_tx++] = m;
					else
						rte_pktmbuf_free(m);
				}
				/* Other IPv4 packet
				* TCP (RFSimulator) and SCTP (F1AP) are also on this condition
				*/
				else
					rte_pktmbuf_free(m);
			}
			else
				rte_pktmbuf_free(m);
		}

		if (nb_tx) {
			nb_tx_res = rte_eth_tx_burst(dn_port, 0, ue_pkts_tx, nb_tx);

			if (unlikely(nb_tx_res < nb_tx)) {
				for (i = nb_tx_res; i < nb_tx; i++)
					rte_pktmbuf_free(ue_pkts_tx[i]);
			}
		}
    }
}

static void
dn_main_loop(unsigned lcore_id)
{
	uint16_t i, j, num;
	uint16_t nb_rx, nb_tx;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *m;

	uint16_t ether_type;
	uint16_t src_port, dst_port;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_arp_hdr *arp_hdr;
	struct lcore_conf *conf = &lcore_conf[lcore_id];

	prev_tsc = 0;

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			buffer = tx_buffer[du_port];
			rte_eth_tx_buffer_flush(du_port, 0, buffer);
			prev_tsc = cur_tsc;
		}

		nb_tx = 0;
		nb_rx = rte_eth_rx_burst(dn_port, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
			return;
		}

		if (!nb_rx)
			continue;

		for (i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			rte_prefetch0(rte_pktmbuf_mtod(m, void*));

			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
			ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

			if (likely(ether_type == RTE_ETHER_TYPE_IPV4)) {
				ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
				src_port = 0;

				if (ipv4_hdr->next_proto_id == IP_PROTO_ICMP) {
					if (downlink_process(m) < 0)
						rte_pktmbuf_free(m);
					continue;
				}
				else if (ipv4_hdr->next_proto_id == IP_PROTO_UDP) {
					udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
					src_port = rte_be_to_cpu_16(udp_hdr->src_port);
					dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
				}
				else if (ipv4_hdr->next_proto_id == IP_PROTO_TCP) {
					tcp_hdr = (struct rte_tcp_hdr*) (ipv4_hdr + 1);
					src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
					dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
				}

				if ((src_port >= 5200 && src_port <= 5300) || (dst_port >= 5200 && dst_port <= 5300)) {
					if (downlink_process(m) < 0)
						rte_pktmbuf_free(m);
				}
			}
			/* Direct free */
			else
				rte_pktmbuf_free(m);
		}
    }
}

static int
main_loop(__rte_unused void *arg)
{
	unsigned lcore_id;
	uint8_t role, port_id;
	int cu_tx_queue;

	lcore_id = rte_lcore_id();
	role = lcore_conf[lcore_id].role;

	if (role == LCORE_DU) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for receiving packets from DU port %u\n",
			lcore_id, du_port);
		du_main_loop(lcore_id);
	}
	else if (role == LCORE_DN) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for receiving packets from DN port (%u)\n", lcore_id, dn_port);
		dn_main_loop(lcore_id);
	}
	else if (role == LCORE_STAT) {
		RTE_LOG(INFO, DU_UP, "entering main loop on locre %u for collectin statistics\n", lcore_id);
		stat_collect_loop();
	}
	else {
		RTE_LOG(INFO, DU_UP, "lcore %u has nothing to do\n", lcore_id);
	}

    return 0;
}

static void
print_app_config()
{
	

	fflush(stdout);
}

static void
port_init()
{
	int ret, i;
	uint8_t port_id, nb_tx_queue;
	uint16_t lcore_rx_id;
	uint32_t lcore_socket_id;
	char pool_name[MAX_POOL_NAME_LEN];
	struct rte_ring *ring;

	/* Initialize each port */
	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_mempool *mbuf_pool;

		if ((port_mask & (1 << port_id)) == 0) {
			printf("Skip port %u...\n", port_id);
			continue;
		}
		printf("Initializing port %u\n", port_id);
		fflush(stdout);

		/* set pktmbuf pool */
		snprintf(pool_name, sizeof(pool_name), "mbuf_pool_%u", port_id);
		mbuf_pool = rte_pktmbuf_pool_create(pool_name, NB_MBUF,
			MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
		
		if (mbuf_pool == NULL)
			rte_exit(EXIT_FAILURE, "pktmbuf_pool for port %u is NULL\n", port_id);

		pktmbuf_pools[port_id] = mbuf_pool;

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE, "Could not get device information of port %u: %s\n", port_id, strerror(-ret));
		}

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE) {
			RTE_LOG(INFO, DU_UP, "Device %s supports DEV_TX_OFFLOAD_MBUF_FAST_FREE\n", dev_info.device->name);
			local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		}
		else {
			RTE_LOG(INFO, DU_UP, "Device %s doesn't support DEV_TX_OFFLOAD_MBUF_FAST_FREE\n", dev_info.device->name);
		}

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MT_LOCKFREE) {
			RTE_LOG(INFO, DU_UP, "Device %s supports DEV_TX_OFFLOAD_MT_LOCKFREE\n", dev_info.device->name);
			local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MT_LOCKFREE;
		}
		else {
			RTE_LOG(INFO, DU_UP, "Device %s doesn't support DEV_TX_OFFLOAD_MT_LOCKFREE\n", dev_info.device->name);
		}
			
		// Configure one TX/RX queue for each port
		nb_tx_queue = 1;
		ret = rte_eth_dev_configure(port_id, 1, nb_tx_queue, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err = %d, port = %u\n",
				  ret, port_id);
		RTE_LOG(INFO, DU_UP, "Create %u TX queues for device %s\n", nb_tx_queue, dev_info.device->name);
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
					     mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err = %d, port = %u\n",
				  ret, port_id);

		/* init one TX queue */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		// Disable L4 Checksum
		txq_conf.offloads &= ~DEV_TX_OFFLOAD_UDP_CKSUM;
		for (i = 0; i < nb_tx_queue; i++) {
			ret = rte_eth_tx_queue_setup(port_id, i, nb_txd,
					rte_eth_dev_socket_id(port_id),
					&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err = %d, port = %u, queue = %d\n",
					ret, port_id, i);
		}
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

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid DU-UP parameters\n");

	ret = load_cfg_profile(cfg_profile);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in loading cfg file\n");

	print_app_config();

	/* Initialize ports */
	port_init();
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
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, SKIP_MAIN);

#ifdef QOS_FLOW_PRESSURE_TEST
	insert_test_set();
#endif /* QOS_FLOW_PRESSURE_TEST */

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
	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}