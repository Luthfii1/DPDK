#include <stdint.h>

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
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_kni.h>

#include "common.h"
#include "arp_table.h"

struct kni_port_params *kni_ue_port_params = NULL;
struct kni_port_params *kni_cu_port_params = NULL;

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t *mac_addr);
static void kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

static int
kni_alloc_internal(struct kni_port_params *params, struct rte_mempool *pktmbuf_pool);

/* Initialize KNI subsystem */
void
init_kni(void)
{
	uint8_t num_of_kni_ports = 0, port_id;
	struct kni_port_params **params = kni_port_params_array;
	const char *kni_ue_if_name = "ue";
	const char *kni_cu_if_name = "cu";

	/* Invoke rte KNI init to preallocate kni ifaces for CU-side and UE-side */
	rte_kni_init(2);

	/* Initialize KNI parameters for UE side */
	kni_ue_port_params =
		rte_zmalloc("KNI_UE_SIDE", sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
	kni_ue_port_params->group_id = ue_ports[0];
	kni_ue_port_params->port_id = ue_ports[0];
	kni_ue_port_params->nb_lcore_k = 0;
	strncpy(kni_ue_port_params->kni_device_name, kni_ue_if_name, strlen(kni_ue_if_name));

	if (kni_alloc_internal(kni_ue_port_params, pktmbuf_pool_ue) < 0) {
		rte_exit(EXIT_FAILURE, "Failed to create UE-side kni device\n");
	}
	rte_atomic32_init(&kni_pause[kni_ue_port_params->group_id]);

	/* Initialize KNI parameters for CU side */
	kni_cu_port_params =
		rte_zmalloc("KNI_CU_SIDE", sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
	kni_cu_port_params->group_id = cu_port;
	kni_cu_port_params->port_id = cu_port;
	kni_cu_port_params->nb_lcore_k = 0;
	strncpy(kni_cu_port_params->kni_device_name, kni_cu_if_name, strlen(kni_cu_if_name));
	
	if (kni_alloc_internal(kni_cu_port_params, pktmbuf_pool_cu) < 0) {
		rte_exit(EXIT_FAILURE, "Failed to create CU-side kni device\n");
	}
	rte_atomic32_init(&kni_pause[kni_cu_port_params->group_id]);
}

static int
kni_alloc_internal(struct kni_port_params *params, struct rte_mempool *pktmbuf_pool)
{
	uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	int ret;

	if (!pktmbuf_pool)
		return -1;

	/* Clear conf at first */
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth-%s", params->kni_device_name);
	conf.group_id = params->group_id;
	conf.mbuf_size = MAX_PACKET_SZ;
	/*
		* The first KNI device associated to a port
		* is the main, for multiple kernel thread
		* environment.
		*/
	if (i == 0) {
		struct rte_kni_ops ops;
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(params->port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				params->port_id, strerror(-ret));

		/* Get the interface default mac address */
		ret = rte_eth_macaddr_get(params->port_id,
			(struct rte_ether_addr *)&conf.mac_addr);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Failed to get MAC address (port %u): %s\n",
				params->port_id, rte_strerror(-ret));

		rte_eth_dev_get_mtu(params->port_id, &conf.mtu);

		conf.min_mtu = dev_info.min_mtu;
		conf.max_mtu = dev_info.max_mtu;

		memset(&ops, 0, sizeof(ops));
		ops.port_id = params->group_id;
		ops.change_mtu = kni_change_mtu;
		ops.config_network_if = kni_config_network_interface;
		ops.config_mac_address = kni_config_mac_address;

		kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
	} else
		kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);

	if (!kni)
		rte_exit(EXIT_FAILURE, "Fail to create kni for "
					"port: %d\n", params->port_id);
	
	params->nb_kni = 1;
	params->kni[0] = kni;

	return 0;
}

static int
kni_free_(struct kni_port_params *parms)
{
	uint8_t i;
	for (i = 0; i < parms->nb_kni; i++) {
		if (rte_kni_release(parms->kni[i])) {
			printf("Fail to release kni\n");
		}			
		parms->kni[i] = NULL;
	}
	return 0;
}

int
kni_free()
{
	kni_free_(kni_ue_port_params);
	rte_free(kni_ue_port_params);
	kni_ue_port_params = NULL;

	kni_free_(kni_cu_port_params);
	rte_free(kni_cu_port_params);
	kni_cu_port_params = NULL;

	return 0;
}

static int
kni_change_mtu_(uint16_t port_id, unsigned int new_mtu)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_conf conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_mempool *pktmbuf_pool = port_id == cu_port ? pktmbuf_pool_cu : pktmbuf_pool_ue;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, DU_UP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, DU_UP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	ret = rte_eth_dev_stop(port_id);
	if (ret != 0) {
		RTE_LOG(ERR, DU_UP, "Failed to stop port %d: %s\n",
			port_id, rte_strerror(-ret));
		return ret;
	}

	memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > RTE_ETHER_MAX_LEN)
		conf.rxmode.offloads |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		conf.rxmode.offloads &= ~DEV_RX_OFFLOAD_JUMBO_FRAME;

	/* mtu + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len = new_mtu + KNI_ENET_HEADER_SIZE +
							KNI_ENET_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(ERR, DU_UP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		RTE_LOG(ERR, DU_UP,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

		return ret;
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
	if (ret < 0) {
		RTE_LOG(ERR, DU_UP, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
		rte_eth_dev_socket_id(port_id), &txq_conf);
	if (ret < 0) {
		RTE_LOG(ERR, DU_UP, "Fail to setup Tx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, DU_UP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;

	rte_atomic32_inc(&kni_pause[port_id]);
	ret =  kni_change_mtu_(port_id, new_mtu);
	rte_atomic32_dec(&kni_pause[port_id]);

	return ret;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, DU_UP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, DU_UP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	rte_atomic32_inc(&kni_pause[port_id]);

	if (if_up != 0) { /* Configure network interface up */
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0) {
			RTE_LOG(ERR, DU_UP, "Failed to stop port %d: %s\n",
				port_id, rte_strerror(-ret));
			rte_atomic32_dec(&kni_pause[port_id]);
			return ret;
		}
		ret = rte_eth_dev_start(port_id);
	} else { /* Configure network interface down */
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0) {
			RTE_LOG(ERR, DU_UP, "Failed to stop port %d: %s\n",
				port_id, rte_strerror(-ret));
			rte_atomic32_dec(&kni_pause[port_id]);
			return ret;
		}
	}

	rte_atomic32_dec(&kni_pause[port_id]);

	if (ret < 0)
		RTE_LOG(ERR, DU_UP, "Failed to start port %d\n", port_id);

	return ret;
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t *mac_addr)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, DU_UP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, DU_UP, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, DU_UP, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

static void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		pkts[i] = NULL;
	}
}

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
void
kni_ingress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num = 0;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, DU_UP, "Error receiving from eth\n");
			return;
		}
		/* Burst tx to kni */
		num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		if (num)
			kni_stats[port_id].rx_packets += num;

		
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			kni_stats[port_id].rx_dropped += nb_rx - num;
		}
	}
}

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
void
kni_egress(struct kni_port_params *p)
{
	uint8_t i, j, tx_flag;
	uint16_t port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *pkt;

	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_arp_hdr *arp_hdr;

	struct arp_table_entry *arp_entry;

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, DU_UP, "Error receiving from KNI\n");
			return;
		}
		for (j = 0; j < num; j++) {
			pkt = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(pkt, void*));

			eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
			num = 0;

			if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
				arp_hdr = (struct rte_arp_hdr*) (eth_hdr + 1);
				arp_entry = arp_table_get_entry(arp_hdr->arp_data.arp_tip);
				if (arp_entry)
					num = rte_eth_tx_burst(arp_entry->port, 0, &pkt, 1);	
			}
			else if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_IPV4) {
				ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
				arp_entry = arp_table_get_entry(ipv4_hdr->dst_addr);
				if (arp_entry)
					num = rte_eth_tx_burst(arp_entry->port, 0, &pkt, 1);
			}

			if (!num) {
				rte_pktmbuf_free(pkt);
				pkts_burst[j] = NULL;
			}
		}

		// if (nb_tx)
		// 	kni_stats[port_id].tx_packets += nb_tx;

		rte_kni_handle_request(p->kni[i]);
		// if (unlikely(nb_tx < num)) {
		// 	/* Free mbufs not tx to NIC */
		// 	kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
		// 	kni_stats[port_id].tx_dropped += num - nb_tx;
		// }
	}
}