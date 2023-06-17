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
#include "drb_table.h"

#define MAX_POOL_NAME_LEN 32
#define CMD_LINE_OPT_CFG_FILE "cfg-file"

#ifdef PING_TEST
static struct rte_ether_addr target_mac;
#endif

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
uint16_t ue_ports[RTE_MAX_ETHPORTS];
uint16_t cu_port;

static volatile uint16_t nb_active_non_gbr_flow = 0;
static volatile uint16_t nb_active_qos_flow = 0;
static uint64_t rest_of_bandwidth = 10000000000;

struct rte_ether_addr cu_up_mac;
uint32_t du_f1u_ip, du_dl_trunk_ip;
static struct timespec start_time;

static uint64_t ul_current_tsc;
static uint64_t dl_current_tsc;

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
			ue_info = runtime_ue_array[i];
			nb_qos_flow = ue_info->nb_qos_flow;

			for (j = 0; j < nb_qos_flow; j++) {
				qos_flow = ue_info->qos_flow_array[j];
				clock_gettime(CLOCK_REALTIME, &end_time);

				duration_10msec = (end_time.tv_sec - start_time.tv_sec) * 100 + (end_time.tv_nsec - start_time.tv_nsec) / 10000000;
				duration = (double) duration_10msec / 100.0;
				if (duration > 0) {
					rx_bps = ((double) qos_flow->statistics.ul_rx_bytes * 8) / duration;
					tx_bps = ((double) qos_flow->statistics.ul_tx_bytes * 8) / duration;
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
					qos_flow->statistics.ul_rx_pkt,
					qos_flow->statistics.ul_tx_pkt,
					qos_flow->statistics.ul_rx_bytes,
					qos_flow->statistics.ul_tx_bytes,
					rx_bps,
					tx_bps
				);

				qos_flow->statistics.iteration = 0;
				qos_flow->statistics.ul_rx_pkt = 0;
				qos_flow->statistics.ul_tx_pkt = 0;
				qos_flow->statistics.ul_rx_bytes = 0;
				qos_flow->statistics.ul_tx_bytes = 0;
			}
		}

		start_time = end_time;
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

static char*
role_to_string(uint8_t role)
{
	switch (role)
	{
	case ROLE_UE:
		return "ROLE_UE";
	case ROLE_CU:
		return "ROLE_CU";
	default:
		break;
	}
	return "Unknown";
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
	char *madatory_role_name[3] = {
		"UE",
		"CU RX",
		"KNI"
	};

	printf("lcore %u config: \n", lcore_id);

	if (role == LCORE_UE || role == LCORE_CU_RX || role == LCORE_KNI) {
		printf("  - Role = %s\n", madatory_role_name[role - 1]);

		printf("  - control port = [");
		for (i = 0; i < lcore_conf[lcore_id].nb_port; i++) {
			printf(" %u", lcore_conf[lcore_id].ports[i]);
		}
		printf(" ]\n");
	}
	else if (role == LCORE_TIMER) {
		printf("  - Role = TIMER\n");
	}
#ifdef STAT_COLLECT
	else if (role == LCORE_STAT) {
		printf("  - Role = STAT Collector\n");
	}
#endif

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

static int
reconfigure_trTCM_profile(struct qos_flow_params *qos_flow, uint64_t allocated_gfbr, uint64_t allocated_mfbr)
{
    int ret;

    // unit = Bytes
    qos_flow->trtcm_params->cir = allocated_gfbr / 8;
    qos_flow->trtcm_params->pir = allocated_mfbr / 8;
    // 10 Gbps in 10 ms
    // unit = Bytes
    qos_flow->trtcm_params->cbs = 10000000000 / 8 / 100;
    qos_flow->trtcm_params->pbs = 10000000000 / 8 / 100;

	// RTE_LOG(INFO, DU_UP, "Configure QoS flow %u meter (CIR, PIR) byte-per-second = (%lu, %lu)\n",
	// 	qos_flow->qfi, qos_flow->trtcm_params->cir, qos_flow->trtcm_params->pir);

    ret = rte_meter_trtcm_profile_config(qos_flow->trtcm_profile, qos_flow->trtcm_params);

    rte_meter_trtcm_config(qos_flow->trtcm_runtime_ctxt, qos_flow->trtcm_profile);
	rte_meter_trtcm_config(qos_flow->dl_trtcm_runtime_ctxt, qos_flow->trtcm_profile);

    return 0;
}

static inline void
adjust_meter() {
	int i, j;
	uint64_t rest_bw_for_allocate, avg, shared;
	uint16_t nb_gbr_flow, nb_ngbr_flow, nb_wait_flow;
	struct qos_flow_params *qos_flow;
	struct qos_flow_params **gbr_flow_array, **ngbr_flow_array;

	nb_wait_flow = nb_active_qos_flow;
	rest_bw_for_allocate = rest_of_bandwidth;

	if (nb_wait_flow > nb_active_non_gbr_flow) {
		for (i = 0; i < nb_ue; i++) {
			uint16_t nb_gbr_flow = runtime_ue_array[i]->nb_gbr_flow;
			gbr_flow_array = runtime_ue_array[i]->gbr_flow_ptr;

			for (j = 0; j < nb_gbr_flow; j++) {
				qos_flow = gbr_flow_array[j];
				if (!qos_flow->is_active)
					continue;

				avg = rest_bw_for_allocate / nb_wait_flow;
				shared = RTE_MIN(avg, qos_flow->mfbr - qos_flow->gfbr);

				reconfigure_trTCM_profile(qos_flow, qos_flow->gfbr, qos_flow->gfbr + shared);
				// Update rest bandwidth and number of waiting allocated flows
				rest_bw_for_allocate -= shared;
				nb_wait_flow--;
			}
		}
	}

	if (nb_active_non_gbr_flow) {
		avg = rest_bw_for_allocate / nb_wait_flow;
		for (i = 0; i < nb_ue; i++) {
			uint16_t nb_ngbr_flow = runtime_ue_array[i]->nb_ngbr_flow;
			ngbr_flow_array = runtime_ue_array[i]->ngbr_flow_ptr;

			for (j = 0; j < nb_ngbr_flow; j++) {
				qos_flow = ngbr_flow_array[j];
				if (!qos_flow->is_active)
					continue;

				reconfigure_trTCM_profile(qos_flow, avg, avg);
			}
		}
	}
}

static void
set_qos_flow_active(struct qos_flow_params *qos_flow)
{
	int i, j;
	uint32_t qf_mutex;
	struct ue_info *ue;
	struct qos_flow_params *qos_flow_ptr;
	uint64_t rest_of_bandwidth_for_nongbr;

	uint64_t rest_bw_for_allocate, avg, shared;
	uint16_t nb_wait_flows;

	while (1) {
		qf_mutex = rte_atomic32_test_and_set(&qos_flow_config_mutex);

		if (likely(qf_mutex)) {
			break;
		}
	}

	if (unlikely(qos_flow->is_active))
		return;

	qos_flow->is_active = true;

	if (qos_flow->type == QOS_FLOW_TYPE_GBR) {
		rest_of_bandwidth -= qos_flow->gfbr;
	}
	else {
		nb_active_non_gbr_flow++;
	}
	nb_active_qos_flow++;

	adjust_meter();

	rte_atomic32_dec(&qos_flow_config_mutex);
}

static void
timer_main_loop(unsigned lcore_id)
{
	uint8_t reconfig_flag = false;
	uint16_t i, j;
	struct ue_info *ue;
	struct qos_flow_params *qos_flow;
	uint64_t current_tsc, last_tsc;
	uint64_t start_polling_tsc, end_polling_tsc;
	uint64_t rest_of_bandwidth_for_nongbr;
	int64_t sleep_time;
	uint32_t qf_mutex;

	uint16_t nb_inactive_flow;

	const uint64_t IDLE_TIME = rte_get_tsc_hz() * 10;
	const uint64_t SLEEP_CYCLES = rte_get_tsc_hz() / 5;
	const uint64_t CYCLE_PER_US = rte_get_tsc_hz() / 1000000;

	last_tsc = rte_rdtsc();
	current_tsc = rte_rdtsc();
	current_tsc = rte_rdtsc();

	RTE_LOG(INFO, DU_UP, "CPU cycle cost of rte_rdstc() = %lu\n", (current_tsc - last_tsc) / 2);
	RTE_LOG(INFO, DU_UP, "IDLE TIME = %lu\n", IDLE_TIME);
	RTE_LOG(INFO, DU_UP, "Sleep Cycles = %lu\n", SLEEP_CYCLES);
	RTE_LOG(INFO, DU_UP, "CPU Cycles per us = %lu\n", CYCLE_PER_US);

	while (!force_quit) {
		start_polling_tsc = rte_rdtsc();
		qf_mutex = rte_atomic32_test_and_set(&qos_flow_config_mutex);

		if (unlikely(!qf_mutex)) {
			continue;
		}

		current_tsc = rte_rdtsc();
		nb_inactive_flow = 0;
		for (i = 0; i < nb_ue; i++) {
			ue = runtime_ue_array[i];

			for (j = 0; j < ue->nb_qos_flow; j++) {
				qos_flow = ue->qos_flow_array[j];
				if (!qos_flow->is_active)
					continue;
				
				// Set QoS flow inactive
				if (current_tsc > qos_flow->last_active_tsc && (current_tsc - qos_flow->last_active_tsc) >= IDLE_TIME) {
					reconfig_flag = true;
					qos_flow->is_active = false;

					if (qos_flow->type == QOS_FLOW_TYPE_GBR) {
						rest_of_bandwidth += qos_flow->gfbr;
					}
					else {
						nb_active_non_gbr_flow--;
					}
					nb_active_qos_flow--;
					nb_inactive_flow++;
					// RTE_LOG(INFO, DU_UP, "QoS Flow %u of UE %04x is set to inactive after %lu tsc\n",
					// 	qos_flow->qfi, ue->rnti, current_tsc - qos_flow->last_active_tsc);
				}
			}
		}

		if (unlikely(reconfig_flag && nb_active_qos_flow)) {
			// RTE_LOG(INFO, DU_UP, "Set %u qos flows inactive\n", nb_inactive_flow);
			adjust_meter();
		}
		reconfig_flag = false;

		rte_atomic32_dec(&qos_flow_config_mutex);
		end_polling_tsc = rte_rdtsc();
		sleep_time = (SLEEP_CYCLES - (end_polling_tsc - start_polling_tsc)) / CYCLE_PER_US;

		if (likely(sleep_time > 0))
			rte_delay_us_sleep(sleep_time);
		else
			RTE_LOG(ERR, DU_UP, "No sleep time\n");
	}
}

#ifdef STAT_COLLECT

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
	double ul_rx_bps, dl_rx_bps, tx_bps;
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
			fprintf(stat, "    #");
			for (int i = 0; i < nb_ue; i++) {
				ue = runtime_ue_array[i];
				qos_flow_arr = ue->qos_flow_array;
				for (int j = 0; j < ue->nb_qos_flow; j++) {
					qos_flow = qos_flow_arr[j];
					fprintf(stat, "\t%04X-%02u-UL-RX", ue->rnti, qos_flow->qfi);
					fprintf(stat, "\t%04X-%02u-DL-RX", ue->rnti, qos_flow->qfi);
				}
			}
			fprintf(stat, "\n");
			print_title = 0;
			clock_gettime(CLOCK_REALTIME, &stat_start_time);
		}

		sleep(1);

		fprintf(stat, "%5lu", time_second);

		for (int i = 0; i < nb_ue; i++) {
			ue = runtime_ue_array[i];
			qos_flow_arr = ue->qos_flow_array;
			for (int j = 0; j < ue->nb_qos_flow; j++) {
				qos_flow = qos_flow_arr[j];
				qos_flow_stats = &qos_flow->statistics;
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

				fprintf(stat, "\t%13.2f", ul_rx_bps / 1000000000);
				fprintf(stat, "\t%13.2f", dl_rx_bps / 1000000000);

				qos_flow_stats->ul_rx_pkt = qos_flow_stats->dl_rx_pkt = 0;
				qos_flow_stats->ul_tx_pkt = qos_flow_stats->dl_tx_pkt = 0;
				qos_flow_stats->ul_rx_bytes = qos_flow_stats->dl_rx_bytes = 0;
				qos_flow_stats->ul_tx_bytes = qos_flow_stats->dl_tx_bytes = 0;
			}
		}
		fprintf(stat, "\n");

		time_second++;
		stat_start_time = stat_end_time;
	}

	fclose(stat);
}

#endif

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

	// uint8_t drb_id;
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
	uint16_t origin_pkt_len, meter_used_pkt_len;
	enum rte_color pkt_color = RTE_COLOR_GREEN;
	struct drb_params *drb;
	struct qos_flow_params *qos_flow;

	// Get original packet length (frame size - FCS)
	origin_pkt_len = pkt->pkt_len + 24;
	meter_used_pkt_len = origin_pkt_len + 19;

	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

	// After adj
	// +---------------------------------+
	// + DRB Info | PDCP | SDAP | UE Pkt |
	// +---------------------------------+
	drb_ind_hdr = (struct drb_ind_hdr*) ((uint8_t*) (ipv4_hdr + 1) + sizeof(struct rte_udp_hdr));
	// rte_pktmbuf_mtod_offset(pkt, struct drb_ind_hdr*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	// drb_id = drb_ind_hdr->drb_id;

	drb = get_drb_by_rfsim(ipv4_hdr->src_addr, drb_ind_hdr->drb_id);
	if (unlikely(!drb)) {
		RTE_LOG(ERR, DU_UP, "Could not find DRB for RFSim-UP packet\n");
		return -1;
	}
	rte_prefetch0((void*) drb);

	// Retrieve SDAP Header
	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;
	// u8_ptr = (uint8_t*) (drb_ind_hdr + 1);
	sdap_hdr = (struct sdap_hdr*) ((uint8_t*) (drb_ind_hdr + 1) + pdcp_hdr_len);

	// Meter
	qos_flow = drb->qos_flow_ptr[sdap_hdr->qfi];
	if (unlikely(qos_flow == NULL)) {
		RTE_LOG(ERR, DU_UP, "Could not find QoS Flow by QFI %u in uplink flow\n", sdap_hdr->qfi);
		return -1;
	}
	rte_prefetch0((void*) qos_flow);
	qos_flow->statistics.ul_rx_bytes += origin_pkt_len;
	qos_flow->statistics.ul_rx_pkt++;

#ifdef ENABLE_ADAPTIVE_METER
	if (!qos_flow->is_active) {
		if (rest_of_bandwidth == 0)
			return -1;
		// Set QoS flow active
		set_qos_flow_active(qos_flow);
	}
	qos_flow->last_active_tsc = ul_current_tsc;

	pkt_color = rte_meter_trtcm_color_blind_check(
		qos_flow->trtcm_runtime_ctxt, qos_flow->trtcm_profile,
		qos_flow->last_active_tsc, meter_used_pkt_len);
	
#else
	qos_flow->last_active_tsc = ul_current_tsc;
	if (qos_flow->type == QOS_FLOW_TYPE_GBR) {
		pkt_color = rte_meter_trtcm_color_blind_check(
			qos_flow->trtcm_runtime_ctxt, qos_flow->trtcm_profile,
			qos_flow->last_active_tsc, meter_used_pkt_len);
	}
#endif
	if (pkt_color == RTE_COLOR_RED) {
		return -1;
	}

	// Remove DRB Info header
	// +----------------------+
	// | PDCP | SDAP | UE Pkt |
	// +----------------------+
	rte_pktmbuf_adj(
		pkt, 
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct drb_ind_hdr)
	);
	
#ifndef PING_TEST
	// Encapsulate F1-U header
	// +----------------------------------------------------+
	// | Eth | IP | UDP | GTP | NRUP | PDCP | SDAP | UE Pkt |
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
	rte_ether_addr_copy(&port_eth_addr[cu_port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&cu_up_mac, &eth_hdr->d_addr);

	// IPv4
	payload_len -= sizeof(struct rte_ether_hdr);
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->total_length = rte_cpu_to_be_16(payload_len);
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IP_PROTO_UDP;
	ipv4_hdr->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
	ipv4_hdr->src_addr = du_f1u_ip;
	ipv4_hdr->dst_addr = drb->f1u_ul_ip;
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
	// udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
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
	rte_ether_addr_copy(&port_eth_addr[cu_port], &eth_hdr->s_addr);
	rte_ether_addr_copy(&target_mac, &eth_hdr->d_addr);
#endif /* PING TEST */

	// Include FCS
	qos_flow->statistics.ul_tx_bytes += meter_used_pkt_len;
	qos_flow->statistics.ul_tx_pkt++;

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

	const struct drb_params *drb = NULL;
	struct qos_flow_params *qos_flow = NULL;
	const struct arp_table_entry *arp_entry;
	struct ue_info *ue;

	// uint8_t drb_id = 0;
	uint8_t qfi = 0;
	uint16_t tx_port;
	uint32_t dl_teid;
	uint32_t dl_trunk_ip;
	uint16_t pdcp_hdr_len;
	uint16_t gtp_ext_hdr_len = calculate_gtp_ext_hdr_len(sizeof(struct ran_container_type0) + 2);
	const uint16_t dl_trunk_hdr_len =
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
		sizeof(struct rte_udp_hdr) + sizeof(struct drb_ind_hdr);
	uint16_t payload_len;
	uint16_t origin_pkt_len, meter_used_pkt_len;
	enum rte_color pkt_color = RTE_COLOR_GREEN;

	// Get original packet length (except for ethernet header)
	origin_pkt_len = pkt->pkt_len + 24;

	// Use RFSim-UP packet length to meter qos flow (include FCS)
#ifndef PING_TEST
	meter_used_pkt_len = origin_pkt_len - 19;
#else
	meter_used_pkt_len = origin_pkt_len + 33;
#endif
	
	// After adj
	// +--------------------------------------------------+
	// | GTP | GTP EXT INFO | NRUP | PDCP | SDAP | UE Pkt |
	// +--------------------------------------------------+
#ifndef PING_TEST
	// gtp_hdr = (struct rte_gtp_hdr*) rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	gtp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_gtp_hdr*, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr));
	dl_teid = rte_be_to_cpu_32(gtp_hdr->teid);

	u8_ptr = (uint8_t*) (gtp_hdr + 1) + sizeof(struct gtp_ext_info);
	// Get NR-RAN-Container header length
	gtp_ext_hdr_len = (*u8_ptr) << 2;

	drb = get_drb_by_dl_teid(dl_teid);
	if (!drb) {
		RTE_LOG(ERR, DU_UP, "Could not find DRB by DL TEID %08X\n", dl_teid);
		return -1;
	}
	ue = drb->ue;
	rte_prefetch0((void*) drb);

	// Retrieve SDAP Header
	pdcp_hdr_len = drb->dl_pdcp_hdr_type == PDCP_18_BIT ? 3 : 2;
	// u8_ptr = u8_ptr + gtp_ext_hdr_len + pdcp_hdr_len;
	sdap_hdr = (struct sdap_hdr*) (u8_ptr + gtp_ext_hdr_len + pdcp_hdr_len);

	qos_flow = drb->qos_flow_ptr[sdap_hdr->qfi];
	if (qos_flow == NULL) {
		RTE_LOG(ERR, DU_UP, "Could not find QoS Flow by QFI %u in downlink flow\n", sdap_hdr->qfi);
		return -1;
	}
	rte_prefetch0((void*) qos_flow);
	qos_flow->statistics.dl_rx_bytes += origin_pkt_len;
	qos_flow->statistics.dl_rx_pkt++;

	// After adj
	// +----------------------+
	// + PDCP | SDAP | UE Pkt |
	// +----------------------+
	rte_pktmbuf_adj(pkt, 
		sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
		sizeof(struct rte_gtp_hdr) + sizeof(struct gtp_ext_info) + gtp_ext_hdr_len);
#else
	const uint32_t gbr_ue_ip = 171704321; // 10.60.0.1
	const uint32_t ngbr_udp_ue_ip = 171704322; // 10.60.0.2
	const uint32_t ngbr_tcp_ue_ip = 171704323; // 10.60.0.3
	const uint32_t ue1_rfsim_ip = rte_cpu_to_be_32(2886926337);
	const uint32_t ue2_rfsim_ip = rte_cpu_to_be_32(2886926338);
	const uint32_t ue3_rfsim_ip = rte_cpu_to_be_32(2886926339);
	uint32_t dst_ip;
	ipv4_hdr = (struct rte_ipv4_hdr*) rte_pktmbuf_adj(pkt, sizeof(struct rte_ether_hdr));
	dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

	if (dst_ip == gbr_ue_ip)
		drb = get_drb_by_rfsim(ue1_rfsim_ip, 1);
	else if (dst_ip == ngbr_udp_ue_ip)
		drb = get_drb_by_rfsim(ue2_rfsim_ip, 2);
	else if (dst_ip == ngbr_tcp_ue_ip)
		drb = get_drb_by_rfsim(ue3_rfsim_ip, 3);
	else
		return -1;

	qos_flow = &drb->qos_flows[0];
	if (qos_flow == NULL) {
		RTE_LOG(ERR, DU_UP, "Could not find Default QoS Flow for drb %u in downlink flow\n", drb->drb_id);
		return -1;
	}
	
#endif

#ifdef ENABLE_ADAPTIVE_METER
	if (!qos_flow->is_active) {
		if (rest_of_bandwidth == 0)
			return -1;
		// Set QoS flow active
		set_qos_flow_active(qos_flow);
	}
	qos_flow->last_active_tsc = dl_current_tsc;

	pkt_color = rte_meter_trtcm_color_blind_check(
		qos_flow->dl_trtcm_runtime_ctxt, qos_flow->trtcm_profile,
		qos_flow->last_active_tsc, meter_used_pkt_len);

#else
	qos_flow->last_active_tsc = dl_current_tsc;
	if (qos_flow->type == QOS_FLOW_TYPE_GBR) {
		pkt_color = rte_meter_trtcm_color_blind_check(
			qos_flow->dl_trtcm_runtime_ctxt, qos_flow->trtcm_profile,
			qos_flow->last_active_tsc, meter_used_pkt_len);
	}
#endif

	if (pkt_color == RTE_COLOR_RED) {
		return -1;
	}

	dl_trunk_ip = ue->dl_trunk_ip;
	// Retrieve target UE port
	arp_entry = arp_table_get_entry(dl_trunk_ip);
	if (!arp_entry) {
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
	ipv4_hdr->src_addr = du_dl_trunk_ip;
	ipv4_hdr->dst_addr = dl_trunk_ip;
	ipv4_hdr->hdr_checksum = 0;
	// ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	pkt->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
	pkt->l2_len = sizeof(struct rte_ether_hdr);
	pkt->l3_len = sizeof(struct rte_ipv4_hdr);

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

	// Include FCS
	qos_flow->statistics.dl_tx_bytes += meter_used_pkt_len;
	qos_flow->statistics.dl_tx_pkt++;

	rte_eth_tx_buffer(tx_port, 0, tx_buffer[tx_port], pkt);

	return 0;
}


static void
ue_rx_main_loop(unsigned lcore_id/*, uint16_t rx_port, uint16_t cu_tx_queue*/)
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

	int32_t f_pause;
	enum packet_direction pkt_dir;
	struct lcore_conf *conf = &lcore_conf[lcore_id];
	struct kni_port_params *kni_port_param = kni_ue_port_params;

	uint64_t current_tsc;

	while (!force_quit) {
        // cur_tsc = rte_rdtsc();
		f_pause = rte_atomic32_read(&kni_pause[kni_port_param->group_id]);

		if (unlikely(f_pause)) {
			continue;
		}
		for (idx = 0; idx < conf->nb_port; idx++) {
			rx_port = conf->ports[idx];
			nb_tx = 0;
			nb_rx = rte_eth_rx_burst(rx_port, 0, pkts_burst, PKT_BURST_SZ);
			if (unlikely(nb_rx > PKT_BURST_SZ)) {
				RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
				return;
			}

			if (!nb_rx)
				continue;

			ul_current_tsc = rte_rdtsc();

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

					if (src_port == UDP_PORT_UE5G) {
						RTE_LOG(DEBUG, DU_UP, "Receive RFSim-UP packet from port %u\n", m->port);
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
						kni_ingress_send_pkt(kni_port_param, 0, m);
				}
				else if (ether_type == RTE_ETHER_TYPE_ARP) {
					/* ARP packet handling */
					arp_hdr = (struct rte_arp_hdr*) (eth_hdr + 1);
					
					arp_table_insert(rx_port, arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_sha);
					kni_ingress_send_pkt(kni_port_param, 0, m);
				}
				/* Direct free */
				else
					rte_pktmbuf_free(m);
			}

			if (nb_tx) {
				nb_tx_res = rte_eth_tx_burst(cu_port, 0, ue_pkts_tx, nb_tx);

				if (unlikely(nb_tx_res < nb_tx)) {
					for (i = nb_tx_res; i < nb_tx; i++)
						rte_pktmbuf_free(ue_pkts_tx[i]);
				}
			}
		}
    }
}

static void
cu_rx_main_loop(unsigned lcore_id, uint16_t rx_port)
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
	struct rte_arp_hdr *arp_hdr;

	int32_t f_pause;
	uint16_t tx_port;
	struct lcore_conf *conf = &lcore_conf[lcore_id];
	struct kni_port_params *kni_port_param = kni_cu_port_params;

	prev_tsc = 0;

	while (!force_quit) {
        f_pause = rte_atomic32_read(&kni_pause[kni_port_param->group_id]);

		if (unlikely(f_pause)) {
			continue;
		}

		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			for (i = 0; i < nb_ue_port; i++) {
				tx_port = ue_ports[i];
				buffer = tx_buffer[tx_port];

				rte_eth_tx_buffer_flush(tx_port, 0, buffer);
			}
			prev_tsc = cur_tsc;
		}

		nb_tx = 0;
		nb_rx = rte_eth_rx_burst(rx_port, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
			return;
		}

		if (!nb_rx)
			continue;

		dl_current_tsc = rte_rdtsc();

		for (i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			rte_prefetch0(rte_pktmbuf_mtod(m, void*));

			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
			ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

			if (likely(ether_type == RTE_ETHER_TYPE_IPV4)) {
				ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
				src_port = 0;

#ifndef PING_TEST
				/* UDP packet */
				if (ipv4_hdr->next_proto_id == IP_PROTO_UDP) {
					udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
					src_port = rte_be_to_cpu_16(udp_hdr->src_port);
				}
#else
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
					struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr*) (ipv4_hdr + 1);
					src_port = rte_be_to_cpu_16(tcp_hdr->src_port);
					dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
				}

				if ((src_port >= 5201 && src_port <= 5203) || (dst_port >= 5201 && dst_port <= 5203)) {
					if (downlink_process(m) < 0)
						rte_pktmbuf_free(m);
					continue;
				}
#endif

				if (src_port == RTE_GTPU_UDP_PORT) {
					RTE_LOG(DEBUG, DU_UP, "Received F1-U packet at port %u\n", rx_port);
					if (downlink_process(m) < 0)
						rte_pktmbuf_free(m);
				}
				/* Other IPv4 packet
				 * TCP (RFSimulator) and SCTP (F1AP) are also on this condition
				 */
				else
					kni_ingress_send_pkt(kni_port_param, 0, m);
			}
			else if (ether_type == RTE_ETHER_TYPE_ARP) {
				/* ARP packet handling */
				arp_hdr = (struct rte_arp_hdr*) (eth_hdr + 1);
				
				arp_table_insert(rx_port, arp_hdr->arp_data.arp_sip, arp_hdr->arp_data.arp_sha);
				kni_ingress_send_pkt(kni_port_param, 0, m);
			}
			/* Direct free */
			else
				rte_pktmbuf_free(m);
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

	nb_kni = conf->nb_port;

	while (!force_quit) {
		f_pause = rte_atomic32_read(&kni_pause[kni_ue_port_params->group_id]);
		if (likely(!f_pause)) {
			kni_egress(kni_ue_port_params);
		}

		f_pause = rte_atomic32_read(&kni_pause[kni_cu_port_params->group_id]);
		if (likely(!f_pause)) {
			kni_egress(kni_cu_port_params);
		}
	}
}

static int inline
get_cu_tx_queue_id(uint16_t rx_port)
{
	for (int i = 0; i < nb_ue_port; i++) {
		if (ue_ports[i] == rx_port)
			return i;
	}
	return -1;
}

static int
main_loop(__rte_unused void *arg)
{
	unsigned lcore_id;
	uint8_t role, port_id;
	int cu_tx_queue;

	lcore_id = rte_lcore_id();
	role = lcore_conf[lcore_id].role;

	if (role == LCORE_UE) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for receiving packets from UE ports\n",
			lcore_id);
		ue_rx_main_loop(lcore_id/*, port_id, (uint16_t) cu_tx_queue*/);
	}
	else if (role == LCORE_CU_RX) {
		port_id = lcore_conf[lcore_id].ports[0];
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for receiving packets from CU port (%u)\n", lcore_id, port_id);
		cu_rx_main_loop(lcore_id, port_id);
	}
	else if (role == LCORE_KNI) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for transmitting packets from KNI port\n", lcore_id);
		kni_port_main_loop(lcore_id);
	}
#ifdef ENABLE_ADAPTIVE_METER
	else if (role == LCORE_TIMER) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for timer\n", lcore_id);
		timer_main_loop(lcore_id);
	}
#endif
#ifdef STAT_COLLECT
	else if (role == LCORE_STAT) {
		RTE_LOG(INFO, DU_UP, "entering main loop on lcore %u for stat collector\n", lcore_id);
		stat_collect_loop();
	}
#endif
	else {
		RTE_LOG(INFO, DU_UP, "lcore %u has nothing to do\n", lcore_id);
	}

    return 0;
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

	/* init pktmbuf pool for UE side */
	snprintf(pool_name, MAX_POOL_NAME_LEN, "mbuf_pool_kni_ue");
	pktmbuf_pool_ue = rte_pktmbuf_pool_create(pool_name, NB_MBUF_UE_SIDE,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool_ue == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialize mbuf pool for KNI UE side\n");
	}

	/* init pktmbuf pool for CU side */
	snprintf(pool_name, MAX_POOL_NAME_LEN, "mbuf_pool_kni_cu");
	pktmbuf_pool_cu = rte_pktmbuf_pool_create(pool_name, NB_MBUF_CU_SIDE,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool_cu == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialize mbuf pool for KNI CU side\n");
	}

	/********************************* Hardcoded for test ************************************/
#ifndef PING_TEST
	rte_ether_unformat_addr("3c:fd:fe:61:28:80", &cu_up_mac);
	printf("CU-UP MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
				cu_up_mac.addr_bytes[0],
				cu_up_mac.addr_bytes[1],
				cu_up_mac.addr_bytes[2],
				cu_up_mac.addr_bytes[3],
				cu_up_mac.addr_bytes[4],
				cu_up_mac.addr_bytes[5]);
#else
	rte_ether_unformat_addr("3c:fd:fe:61:2a:ad", &target_mac);
	printf("Target MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
				target_mac.addr_bytes[0],
				target_mac.addr_bytes[1],
				target_mac.addr_bytes[2],
				target_mac.addr_bytes[3],
				target_mac.addr_bytes[4],
				target_mac.addr_bytes[5]);
#endif
	/********************************* Hardcoded for test ************************************/

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
	rte_eal_mp_remote_launch(main_loop, NULL, SKIP_MAIN);

#ifdef QOS_FLOW_PRESSURE_TEST
	insert_test_set();
	// print_drb_avl_tree();
	// print_ue_info();
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
	kni_free();
	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}