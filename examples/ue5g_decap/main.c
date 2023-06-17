#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <getopt.h>

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>
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
#include <rte_arp.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

/* Use DPDK pre-defined log type */
#define RTE_LOGTYPE_UE5GDECAP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            64

/* TX drain every ~100us */
#define BURST_TX_DRAIN_US 100

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ * 2

/* Number of RX ring descriptors */
#define NB_RXD                  2048

/* Number of TX ring descriptors */
#define NB_TXD                  2048

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 5; /* default period is 10 seconds */

/* Port mask */
static uint8_t port_mask = 0x3;

/* TX buffer */
static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;
static volatile bool force_quit;
static uint16_t nb_rxd = NB_RXD;
static uint16_t nb_txd = NB_TXD;

/* Default setting of port */
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

/* Ethernet addresses of ports */
static struct rte_ether_addr port_eth_addr[RTE_MAX_ETHPORTS];

/* Per-port statistics struct */
struct port_stats {
	uint64_t tx;
	uint64_t rx;
	uint64_t ue5g_rx;
	uint64_t dropped;
} __rte_cache_aligned;

struct lcore_port_conf {
	unsigned rx_port;
	unsigned is_set;
} __rte_cache_aligned;

struct pdcp_hdr {
	uint8_t first_byte;
	uint8_t last_byte;
} __rte_packed;

struct sdap_hdr {
	uint8_t first_byte;
} __rte_packed;

struct port_stats port_statistics[RTE_MAX_ETHPORTS];
static struct lcore_port_conf rx_port_per_core[RTE_MAX_LCORE];
/* list of enabled ports */
static uint32_t dst_ports[RTE_MAX_ETHPORTS];
static uint64_t dst_eth_addr[RTE_MAX_ETHPORTS];

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	;

#define CMD_LINE_OPT_ETH_DEST "eth-dest"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ETH_DEST_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
	{NULL, 0, 0, 0}
};

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static void
parse_eth_dest(const char *optarg)
{
	uint16_t portid;
	char *port_end;
	uint8_t c, *dest, peer_addr[6];

	errno = 0;
	portid = strtoul(optarg, &port_end, 10);
	if (errno != 0 || port_end == optarg || *port_end++ != ',')
		rte_exit(EXIT_FAILURE,
		"Invalid eth-dest: %s", optarg);
	if (portid >= RTE_MAX_ETHPORTS)
		rte_exit(EXIT_FAILURE,
		"eth-dest: port %d >= RTE_MAX_ETHPORTS(%d)\n",
		portid, RTE_MAX_ETHPORTS);

	if (cmdline_parse_etheraddr(NULL, port_end,
		&peer_addr, sizeof(peer_addr)) < 0)
		rte_exit(EXIT_FAILURE,
		"Invalid ethernet address: %s\n",
		port_end);
	dest = (uint8_t *) &dst_eth_addr[portid];
	for (c = 0; c < 6; c++)
		dest[c] = peer_addr[c];
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret = 0;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF)
	{
		switch (opt) {
			case CMD_LINE_OPT_ETH_DEST_NUM:
				parse_eth_dest(optarg);
				break;
			default:
				return -1;
		}
	}

	return ret;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
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
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid,
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

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nUE5G Packets received: %15"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].ue5g_rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

/* Uplink packet processing */
static int
uplink_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
							  sizeof(struct rte_udp_hdr) + sizeof(struct pdcp_hdr) + sizeof(struct sdap_hdr);

	dst_port = dst_ports[portid];

	/* Decapsulation */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);

	if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		goto arp_out;
	}
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);

	if (ipv4_hdr->next_proto_id != IPPROTO_UDP) {
		goto out;
	}
	udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
	if (udp_hdr->src_port != rte_cpu_to_be_16(9527)) {
		goto out;
	}
	port_statistics[portid].ue5g_rx++;

	rte_pktmbuf_adj(m, (uint16_t) outer_hdr_len);

	eth_hdr = (struct rte_ether_hdr *) rte_pktmbuf_prepend(m, (uint16_t) sizeof(struct rte_ether_hdr));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

out:
	rte_ether_addr_copy(&port_eth_addr[dst_port], &eth_hdr->s_addr);
	rte_ether_addr_copy((struct rte_ether_addr*) &dst_eth_addr[dst_port], &eth_hdr->d_addr);
arp_out:
	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;

	return 0;
}

/* Downlink packet processing */
static void
downlink_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct sdap_hdr *sdap_hdr;
	struct pdcp_hdr *pdcp_hdr;
	// Network presentation
	const char *ue_ip = "10.60.0.1";
	const char *du_outer_ip = "192.168.220.2";
	const char *ue_outer_ip = "192.168.220.1";
	// Network decimal
	uint32_t ue_ip_decimal;
	uint32_t du_outer_ip_decimal;
	uint32_t ue_outer_ip_decimal;
	uint16_t outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) +
							 sizeof(struct pdcp_hdr) + sizeof(struct sdap_hdr);

	dst_port = dst_ports[portid];
	inet_pton(AF_INET, ue_ip, (void*) &ue_ip_decimal);
	inet_pton(AF_INET, du_outer_ip, (void*) &du_outer_ip_decimal);
	inet_pton(AF_INET, ue_outer_ip, (void*) &ue_outer_ip_decimal);

	/* Encapsulation */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr*);
	if (eth_hdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		goto arp_out;
	}
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);

	if (ipv4_hdr->dst_addr != ue_ip_decimal) {
		goto out;
	}

	rte_pktmbuf_adj(m, (uint16_t) sizeof(struct rte_ether_hdr));
	port_statistics[portid].ue5g_rx++;

	// Ethernet header
	eth_hdr = (struct rte_ether_hdr*) rte_pktmbuf_prepend(m, outer_hdr_len);
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

	// IPv4 header
	ipv4_hdr = (struct rte_ipv4_hdr*) (eth_hdr + 1);
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr));
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	ipv4_hdr->src_addr = du_outer_ip_decimal;
	ipv4_hdr->dst_addr = ue_outer_ip_decimal;
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

	// UDP header
	udp_hdr = (struct rte_udp_hdr*) (ipv4_hdr + 1);
	udp_hdr->src_port = rte_cpu_to_be_16(9527);
	udp_hdr->dst_port = rte_cpu_to_be_16(9527);
	udp_hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
	udp_hdr->dgram_cksum = 0;

	// PDCP header
	pdcp_hdr = (struct pdcp_hdr*) (udp_hdr + 1);
	pdcp_hdr->first_byte = 0x80;
	pdcp_hdr->last_byte = 0x2;

	// SDAP header
	sdap_hdr = (struct sdap_hdr*) (pdcp_hdr + 1);
	sdap_hdr->first_byte = 0x89;

out:
	rte_ether_addr_copy(&port_eth_addr[dst_port], &eth_hdr->s_addr);
	rte_ether_addr_copy((struct rte_ether_addr*) &dst_eth_addr[dst_port], &eth_hdr->d_addr);

arp_out:
	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}

static int
main_loop(__rte_unused void *arg)
{
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, UE5GDECAP, "entering main loop on lcore %u\n", lcore_id);

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			portid = dst_ports[rx_port_per_core[lcore_id].rx_port];
			buffer = tx_buffer[portid];
			sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
			if (sent)
				port_statistics[portid].tx += sent;

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		portid = rx_port_per_core[lcore_id].rx_port;
		nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, PKT_BURST_SZ);
		port_statistics[portid].rx += nb_rx;

		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			
			if (portid % 2 == 0) {
				uplink_forward(m, portid);
			}
			else {
				downlink_forward(m, portid);
			}
		}
	}
	return 0;
}

int main(int argc, char** argv) {
    int ret;
	uint16_t nb_ports, portid, lcore_id;
	int last_port = -1;
	unsigned i;
	void *retval;

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* pre-init dst MACs for all ports to 02:00:00:00:00:xx */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		dst_eth_addr[portid] =
			RTE_ETHER_LOCAL_ADMIN_ADDR + ((uint64_t) portid << 40);
	}

	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid UE5G parameters\n");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* Create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialize mbuf pool\n");
		return -1;
	}

	nb_ports = rte_eth_dev_count_avail();

	if (nb_ports < 2)
		rte_exit(EXIT_FAILURE, "There must be more than two physical ports");

	/* Initialize port stats */
	memset(&port_statistics, 0, sizeof(port_statistics));
	
	/* Initialize each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		if (port_mask & (1 << portid) == 0) {
			printf("Skip port %u...\n", portid);
			continue;
		}
		printf("Initializing port %u\n", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE, "Could not get device information of port %u: %s\n", portid, strerror(-ret));
		}

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		// Configure one TX/RX queue for each port
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err = %d, port = %u\n",
				  ret, portid);
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err = %d, port = %u\n",
				 ret, portid);
		ret = rte_eth_macaddr_get(portid,
					  &port_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err = %d, port = %u\n",
				 ret, portid);

		print_ethaddr("SRC MAC Addr:", &port_eth_addr[portid]);
		printf(", ");
		print_ethaddr("DST MAC Addr:",
			(const struct rte_ether_addr *) &dst_eth_addr[portid]);
		printf("\n");
		
		/* Map port to a specific lcore */
		fflush(stdout);
		RTE_LCORE_FOREACH(lcore_id) {
			if (rx_port_per_core[lcore_id].is_set)
				continue;
			rx_port_per_core[lcore_id].rx_port = portid;
			rx_port_per_core[lcore_id].is_set = true;
			printf("lcore %u is bound to port %u\n", lcore_id, portid);
			break;
		}

		fflush(stdout);
		if (last_port >= 0) {
			dst_ports[last_port] = portid;
			dst_ports[portid] = last_port;
			printf("port pair (%u, %u)\n", last_port, portid);
			last_port = -1;
		}
		else {
			last_port = portid;
		}
		
		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		// Disable UDP Checksum
		rxq_conf.offloads &= ~DEV_RX_OFFLOAD_UDP_CKSUM;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err = %d, port = %u\n",
				  ret, portid);

		/* init one TX queue */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		// Disable UDP Checksum
		rxq_conf.offloads &= ~DEV_TX_OFFLOAD_UDP_CKSUM;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err = %d, port = %u\n",
				ret, portid);
		
		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(PKT_BURST_SZ), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], PKT_BURST_SZ);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);
		
		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n", portid);
		
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err = %d, port = %u\n",
				  ret, portid);

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);

		printf("Complete initialization of port %u\n", portid);
	}
	
	check_all_ports_link_status(port_mask);

	/* Launch main loop on each lcore */
	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %u...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err = %d, port = %d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}