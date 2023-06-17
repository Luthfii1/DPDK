/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>

#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_memcpy.h>
#include <rte_byteorder.h>
#include <rte_branch_prediction.h>

#include <rte_sched.h>
#include <rte_meter.h>

#include "main.h"

/*
 * QoS parameters are encoded as follows:
 *		Outer VLAN ID defines subport
 *		Inner VLAN ID defines pipe
 *		Destination IP host (0.0.0.XXX) defines queue
 * Values below define offset to each field from start of frame
 */
#define SUBPORT_OFFSET	7
#define PIPE_OFFSET		9
#define QUEUE_OFFSET	20
#define COLOR_OFFSET	19

#define FUNC_METER(m, p, time, pkt_len)	\
	rte_meter_trtcm_color_blind_check(m, p, time, pkt_len)
#define FUNC_CONFIG  rte_meter_trtcm_config
#define FLOW_METER   struct rte_meter_trtcm
#define PROFILE      app_trtcm_profile

enum policer_action {
		GREEN = RTE_COLOR_GREEN,
		YELLOW = RTE_COLOR_YELLOW,
		RED = RTE_COLOR_RED,
		DROP = 3,
};

enum policer_action policer_table[RTE_COLORS][RTE_COLORS] =
{
	{ GREEN, RED, RED},
	{ DROP, YELLOW, RED},
	{ DROP, DROP, RED}
};

struct rte_meter_trtcm_profile app_trtcm_profile;
struct rte_meter_trtcm_params app_trtcm_params = {
	.cir = 1000000 * 750,  // 6G
	.pir = 1000000 * 1000, // 8G
	.cbs = 1000000 * 125,
	.pbs = 1000000 * 125
};

#define APP_FLOWS_MAX        256
#define APP_PKT_FLOW_POS      33

FLOW_METER app_flows[APP_FLOWS_MAX];
int back_core = -1;
int back_port_rx = 2;
int back_port_tx[3] = {0, 1, 2};

struct flow_bm_param {
	uint16_t cnt;
	uint16_t quota;
};

#define NB_RX_PORT 2
struct flow_bm_param bm_param[NB_RX_PORT] = {
	{
		.cnt = 3,
		.quota = 3
	},
	{
		.cnt = 1,
		.quota = 1
	}
};
struct flow_bm_param tot_bm_param = {
	.cnt = 4,
	.quota = 4,
};

static int
app_configure_flow_table(void)
{
	uint32_t i;
	int ret;

	ret = rte_meter_trtcm_profile_config(&app_trtcm_profile,
		&app_trtcm_params);
	if (ret)
		return ret;

	for (i = 0; i < APP_FLOWS_MAX; i++) {
		ret = FUNC_CONFIG(&app_flows[i], &PROFILE);
		if (ret)
			return ret;
	}

	return 0;
}

static inline int
app_pkt_handle(struct rte_mbuf *pkt, uint64_t time)
{
	uint8_t output_color;
	uint8_t *pkt_data = rte_pktmbuf_mtod(pkt, uint8_t *);
	uint32_t pkt_len = rte_pktmbuf_pkt_len(pkt) - sizeof(struct rte_ether_hdr);
	uint8_t flow_id = (uint8_t)(pkt_data[APP_PKT_FLOW_POS]) & (APP_FLOWS_MAX - 1);

	/* color input is not used for blind modes */
	output_color = (uint8_t) FUNC_METER(&app_flows[flow_id],
		&PROFILE,
		time,
		pkt_len);

	return output_color;
}

static inline int
get_pkt_sched_by_port(struct rte_mbuf *m, uint16_t in_port, uint32_t *subport, uint32_t *pipe,
			uint32_t *traffic_class, uint32_t *queue, uint32_t *color)
{
	uint64_t current_time;
	uint16_t pipe_queue;

	// Only port 0 needs to perform metering
	if (in_port == 0) {
		current_time = rte_rdtsc();
		*color = app_pkt_handle(m, current_time);
	}
	else {
		*color = RTE_COLOR_YELLOW;
	}

	*subport = 0;
	*pipe = 0;

	if (*color == RTE_COLOR_GREEN) {
		pipe_queue = 0;
	}
	else if (*color == RTE_COLOR_YELLOW) {
		if (in_port == 0) {
			pipe_queue = 1;
		}
		else
			pipe_queue = RTE_SCHED_TRAFFIC_CLASS_BE;
		if (in_port != 0) {
			pipe_queue++;
		}
	}

	*traffic_class = pipe_queue > RTE_SCHED_TRAFFIC_CLASS_BE ?
			RTE_SCHED_TRAFFIC_CLASS_BE : pipe_queue;
	*queue = pipe_queue - *traffic_class;

	return 0;
}

static inline int
get_pkt_sched(struct rte_mbuf *m, uint32_t *subport, uint32_t *pipe,
			uint32_t *traffic_class, uint32_t *queue, uint32_t *color)
{
	uint16_t *pdata = rte_pktmbuf_mtod(m, uint16_t *);
	uint16_t pipe_queue;

	/* Outer VLAN ID (12-bit) */
	// *subport = (rte_be_to_cpu_16(pdata[SUBPORT_OFFSET]) & 0x0FFF) &
	// 	(port_params.n_subports_per_port - 1);
	*subport = 0;

	/* Inner VLAN ID (12-bit) */
	// *pipe = (rte_be_to_cpu_16(pdata[PIPE_OFFSET]) & 0x0FFF) &
	// 	(subport_params[*subport].n_pipes_per_subport_enabled - 1);
	*pipe = 0;

	pipe_queue = active_queues[(pdata[QUEUE_OFFSET] >> 8) % n_active_queues];

	/* Traffic class (Destination IP) */
	*traffic_class = pipe_queue > RTE_SCHED_TRAFFIC_CLASS_BE ?
			RTE_SCHED_TRAFFIC_CLASS_BE : pipe_queue;

	/* Traffic class queue (Destination IP) */
	*queue = pipe_queue - *traffic_class;

	/* Color (Destination IP) */
	*color = pdata[COLOR_OFFSET] & 0x03;

	return 0;
}

void
app_rx_thread(struct thread_conf **confs)
{
	uint32_t i, nb_rx;
	struct rte_mbuf *rx_mbufs[burst_conf.rx_burst] __rte_cache_aligned;
	struct rte_mbuf *tx_mbufs[burst_conf.rx_burst] __rte_cache_aligned;
	struct thread_conf *conf;
	int conf_idx = 0;
	int nb_tx, act_nb_tx;

	uint32_t subport;
	uint32_t pipe;
	uint32_t traffic_class;
	uint32_t queue;
	uint32_t color;

	app_configure_flow_table();

	while ((conf = confs[conf_idx]) && !force_quit) {
		// if (bm_param[conf->rx_port].cnt) {
			nb_rx = rte_eth_rx_burst(conf->rx_port, conf->rx_queue, rx_mbufs,
					burst_conf.rx_burst);
			nb_tx = 0;

			if (likely(nb_rx != 0)) {
				APP_STATS_ADD(conf->stat.nb_rx, nb_rx);

				for(i = 0; i < nb_rx; i++) {
					get_pkt_sched_by_port(rx_mbufs[i], conf->rx_port,
							&subport, &pipe, &traffic_class, &queue, &color);
					// Drop color RED packet
					if (color == RTE_COLOR_RED) {
						rte_pktmbuf_free(rx_mbufs[i]);
						APP_STATS_ADD(conf->stat.nb_drop, 1);
						continue;
					}

					tx_mbufs[nb_tx] = rx_mbufs[i];
					// rte_sched_port_pkt_write(conf->sched_port,
					// 	tx_mbufs[nb_tx],
					// 	subport, pipe,
					// 	traffic_class, queue,
					// 	(enum rte_color) color);
					nb_tx++;
				}

				act_nb_tx = rte_ring_sp_enqueue_burst(conf->rx_ring, (void **)tx_mbufs, nb_tx, NULL);
				if (unlikely(act_nb_tx < nb_tx)) {
					for(i = act_nb_tx; i < nb_tx; i++) {
						rte_pktmbuf_free(tx_mbufs[i]);
					}
					APP_STATS_ADD(conf->stat.nb_drop, nb_tx - act_nb_tx);
				}
			}

		// 	bm_param[conf->rx_port].cnt--;
		// 	tot_bm_param.cnt--;
		// }

		// if (bm_param[conf->rx_port].cnt == 0) {
			conf_idx++;
			if (confs[conf_idx] == NULL)
				conf_idx = 0;
		// }

		// if (tot_bm_param.cnt == 0) {
		// 	tot_bm_param.cnt = tot_bm_param.quota;
		// 	for (i = 0; i < NB_RX_PORT; i++) {
		// 		bm_param[i].cnt = bm_param[i].quota;
		// 	}
		// }
	}
}



/* Send the packet to an output interface
 * For performance reason function returns number of packets dropped, not sent,
 * so 0 means that all packets were sent successfully
 */

static inline void
app_send_burst(struct thread_conf *qconf)
{
	struct rte_mbuf **mbufs;
	uint32_t n, ret;

	mbufs = (struct rte_mbuf **)qconf->m_table;
	n = qconf->n_mbufs;

	do {
		ret = rte_eth_tx_burst(qconf->tx_port, qconf->tx_queue, mbufs, (uint16_t)n);
		/* we cannot drop the packets, so re-send */
		/* update number of packets to be sent */
		n -= ret;
		mbufs = (struct rte_mbuf **)&mbufs[ret];
	} while (n);
}


/* Send the packet to an output interface */
static void
app_send_packets(struct thread_conf *qconf, struct rte_mbuf **mbufs, uint32_t nb_pkt)
{
	uint32_t i, len;

	len = qconf->n_mbufs;
	for(i = 0; i < nb_pkt; i++) {
		qconf->m_table[len] = mbufs[i];
		len++;
		/* enough pkts to be sent */
		if (unlikely(len == burst_conf.tx_burst)) {
			qconf->n_mbufs = len;
			app_send_burst(qconf);
			len = 0;
		}
	}

	qconf->n_mbufs = len;
}

void
app_tx_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.qos_dequeue];
	struct thread_conf *conf;
	int conf_idx = 0;
	int retval;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	while ((conf = confs[conf_idx]) && !force_quit) {
		retval = rte_ring_sc_dequeue_bulk(conf->tx_ring, (void **)mbufs,
					burst_conf.qos_dequeue, NULL);
		if (likely(retval != 0)) {
			app_send_packets(conf, mbufs, burst_conf.qos_dequeue);

			conf->counter = 0; /* reset empty read loop counter */
		}

		conf->counter++;

		/* drain ring and TX queues */
		if (unlikely(conf->counter > drain_tsc)) {
			/* now check is there any packets left to be transmitted */
			if (conf->n_mbufs != 0) {
				app_send_burst(conf);

				conf->n_mbufs = 0;
			}
			conf->counter = 0;
		}

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}


void
app_worker_thread(struct thread_conf **confs)
{
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int conf_idx = 0;

	while ((conf = confs[conf_idx]) && !force_quit) {
		uint32_t nb_pkt;

		/* Read packet from the ring */
		nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs,
					burst_conf.ring_burst, NULL);
		if (likely(nb_pkt)) {
			int nb_sent = rte_sched_port_enqueue(conf->sched_port, mbufs,
					nb_pkt);

			APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
			APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
		}

		nb_pkt = rte_sched_port_dequeue(conf->sched_port, mbufs,
					burst_conf.qos_dequeue);
		if (likely(nb_pkt > 0))
			while (rte_ring_sp_enqueue_bulk(conf->tx_ring,
					(void **)mbufs, nb_pkt, NULL) == 0)
				; /* empty body */

		conf_idx++;
		if (confs[conf_idx] == NULL)
			conf_idx = 0;
	}
}


void
app_mixed_thread(struct thread_conf **confs)
{
	uint64_t current_time, last_time, time_diff;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	struct rte_mbuf *mbufs[burst_conf.ring_burst];
	struct thread_conf *conf;
	int i, conf_idx = 0;
	uint8_t retry;
	uint32_t nb_pkt = 0;

	last_time = rte_rdtsc();
	conf_idx = 0;
	retry = 10;

	while ((conf = confs[conf_idx]) && !force_quit) {
		current_time = rte_rdtsc();
		time_diff = current_time - last_time;

		if (unlikely(time_diff > drain_tsc)) {
			rte_eth_tx_buffer_flush(conf->tx_port, 0, back_tx_buffer[conf->tx_port]);
			last_time = current_time;
		}

		if (bm_param[conf->rx_port].cnt) {
			nb_pkt = rte_ring_sc_dequeue_burst(conf->rx_ring, (void **)mbufs,
					burst_conf.ring_burst, NULL);

			// printf("rx_port: %u, received pkt %u\n", conf->rx_port, nb_pkt);
			if (likely(nb_pkt)) {
				int nb_sent = 0;
				for (i = 0; i < nb_pkt; i++) {
					nb_sent += rte_eth_tx_buffer(conf->tx_port, 0, back_tx_buffer[conf->tx_port], mbufs[i]);
				}
				// APP_STATS_ADD(conf->stat.nb_drop, nb_pkt - nb_sent);
				// APP_STATS_ADD(conf->stat.nb_rx, nb_pkt);
				bm_param[conf->rx_port].cnt--;
				tot_bm_param.cnt--;
				retry = 10;
			}
			else {
				retry--;
			}
		}

		if (!bm_param[conf->rx_port].cnt || !retry) {
			conf_idx++;
			if (confs[conf_idx] == NULL)
				conf_idx = 0;
			if (!retry)
				retry = 10;
		}

		if (tot_bm_param.cnt == 0) {
			tot_bm_param.cnt = tot_bm_param.quota;
			for (i = 0; i < NB_RX_PORT; i++) {
				bm_param[i].cnt = bm_param[i].quota;
			}
		}
	}
}

void
app_back_thread(void)
{
	uint64_t current_time, last_time = rte_rdtsc();
	struct rte_mbuf *port_rx_pkts[MAX_PKT_RX_BURST];
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

	const uint32_t ipv4_dst_addr_port_0 = 2886926337; // 172.19.0.1
	const uint32_t ipv4_dst_addr_port_1 = 2886926338; // 172.19.0.2
	const uint32_t ipv4_dst_addr_port_2 = 2886926339; // 172.19.0.3

	while (!force_quit) {
		uint64_t time_diff;
		int i, nb_rx;

		/* Mechanism to avoid stale packets in the output buffer */
		current_time = rte_rdtsc();
		time_diff = current_time - last_time;
		if (unlikely(time_diff > drain_tsc)) {
			/* Flush tx buffer */
			if (back_tx_buffer[0] != NULL)
				rte_eth_tx_buffer_flush(back_port_tx[0], 0, back_tx_buffer[0]);
			if (back_tx_buffer[1] != NULL)
				rte_eth_tx_buffer_flush(back_port_tx[1], 0, back_tx_buffer[1]);
			// if (back_tx_buffer[2] != NULL)
			// 	rte_eth_tx_buffer_flush(back_port_tx[2], 0, back_tx_buffer[2]);
			last_time = current_time;
		}

		/* Read packet burst from NIC RX from port_rx */
		nb_rx = rte_eth_rx_burst(back_port_rx, 0, port_rx_pkts, MAX_PKT_RX_BURST);

		/* Handle packets */
		for (i = 0; i < nb_rx; i ++) {
			struct rte_mbuf *pkt = port_rx_pkts[i];
			struct rte_ether_hdr *eth_hdr;
			struct rte_ipv4_hdr *ipv4_hdr;

			eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
			if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
				rte_pktmbuf_free(pkt);
				continue;
			}
			ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);

			if (rte_be_to_cpu_32(ipv4_hdr->dst_addr) == ipv4_dst_addr_port_0) {
				rte_eth_tx_buffer(back_port_tx[0], 0, back_tx_buffer[0], pkt);
			}
			else if (rte_be_to_cpu_32(ipv4_hdr->dst_addr) == ipv4_dst_addr_port_1) {
				rte_eth_tx_buffer(back_port_tx[1], 0, back_tx_buffer[1], pkt);
			}
			else if (rte_be_to_cpu_32(ipv4_hdr->dst_addr) == ipv4_dst_addr_port_2) {
				rte_eth_tx_buffer(back_port_tx[2], 0, back_tx_buffer[2], pkt);
			}
			else {
				rte_pktmbuf_free(pkt);
				continue;
			}			
		}
	}
}