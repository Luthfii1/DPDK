/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

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
/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_APP RTE_LOGTYPE_USER1

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
#define NB_MBUF                 (8192 * 16)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            64

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ * 2

/* Number of RX ring descriptors */
#define NB_RXD                  2048

/* Number of TX ring descriptors */
#define NB_TXD                  2048

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_US_PER_SECOND       1000000
#define KNI_SECOND_PER_DAY      86400

#define KNI_MAX_KTHREAD 32
/*
 * Structure of port parameters
 */
struct kni_port_params {
	uint16_t port_id;/* Port ID */
	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;

static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

struct ue_info {
	uint32_t ip;
	uint8_t mac[6];
	uint32_t ul_teid;
	uint32_t dl_teid;
};

static struct ue_info ue_info_array[64];
static uint32_t ue_count = 0;
/* Options for configuring ethernet port */
static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
	/*.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.offloads = DEV_RX_OFFLOAD_RSS_HASH,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IPV4,
			// .rss_hf = ETH_RSS_IPV4 | ETH_RSS_L2_PAYLOAD | ETH_RSS_NONFRAG_IPV4_UDP | ETH_RSS_NONFRAG_IPV4_TCP,	
		},
	},*/
};

/* Mempool for mbufs */
static struct rte_mempool * pktmbuf_pool = NULL;

/* Mask of enabled ports */
static uint32_t ports_mask = 0;
/* Ports set in promiscuous mode off by default. */
static int promiscuous_on = 0;
/* Monitor link status continually. off by default. */
static int monitor_links;

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

typedef struct gtpv1_header {
	uint8_t flags;
	uint8_t type;
	uint16_t length;
	uint32_t teid;
} __attribute__ ((packed)) gtpv1_t;

/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];

static int kni_change_mtu(uint16_t port_id, unsigned int new_mtu);
static int kni_config_network_interface(uint16_t port_id, uint8_t if_up);
static int kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[]);

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t kni_pause = RTE_ATOMIC32_INIT(0);

struct rte_ether_addr agf_uplink_mac, core_downlink_mac;

static uint8_t mac_agf_to_rg[6] = {0x3c, 0xfd, 0xfe, 0xba, 0xf2, 0x23};
static uint8_t mac_agf_to_5gc[6] = {0x3c, 0xfd, 0xfe, 0xba, 0xf2, 0x21};
static uint32_t ip_agf_to_5gc = 174351362;
static uint32_t ip_5gc_to_agf = 174351370;
/* Print out statistics on packets handled */
static void
print_stats(void)
{
	uint16_t i;

	printf("\n**KNI example application statistics**\n"
	       "======  ==============  ============  ============  ============  ============\n"
	       " Port    Lcore(RX/TX)    rx_packets    rx_dropped    tx_packets    tx_dropped\n"
	       "------  --------------  ------------  ------------  ------------  ------------\n");
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!kni_port_params_array[i])
			continue;

		printf("%7d %10u/%2u %13"PRIu64" %13"PRIu64" %13"PRIu64" "
							"%13"PRIu64"\n", i,
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->lcore_tx,
						kni_stats[i].rx_packets,
						kni_stats[i].rx_dropped,
						kni_stats[i].tx_packets,
						kni_stats[i].tx_dropped);
	}
	printf("======  ==============  ============  ============  ============  ============\n");

	fflush(stdout);
}

static void get_ue_info(void)
{
	struct dirent *p_dirent;
	DIR *p_dir;
	ue_count = 0;
	p_dir = opendir("/tmp/");
	if(p_dir == NULL)
	{
		return;
	}
	while((p_dirent = readdir(p_dir)) != NULL)
	{
		if(strncmp(p_dirent->d_name, "imsi-", 5) == 0)
		{
			printf("%s\n", p_dirent->d_name);
			FILE *f;
			char *path;
			path = malloc(25);
			path[0] = '\0';
			strcat(path, "/tmp/");
			strcat(path, p_dirent->d_name);
			
			f = fopen(path, "r");
			if(f == NULL)
			{
				printf("file is null: [%s].\n", path);
				return;
			}
			free(path);
			ssize_t read;
			size_t len = 0;
			char *line = NULL;
			while((read = getline(&line, &len, f)) != -1)
			{
				if(strncmp(line, "ueIp", 4) == 0)
				{
					int ip_len = 0;
					for(uint32_t i=5; i<strlen(line); i++)
					{
						if(line[i] == '.' || (line[i] >= '0' && line[i] <= '9')) ip_len++;
					}
					char ip[ip_len + 1];
					memcpy(ip, &line[5], ip_len);
					ip[ip_len] = '\0';
					char *dot;
					dot = strchr(ip, '.');
					uint8_t ip1_len = dot-ip;
					char ip1[ip1_len+1];
					memcpy(ip1, ip, ip1_len);
					ip1[ip1_len] = '\0';

					dot = strchr(dot+1, '.');
					uint8_t ip2_len = dot-ip-ip1_len-1;
					char ip2[ip2_len+1];
				    memcpy(ip2, &ip[ip1_len+1], ip2_len);	
					ip2[ip2_len] = '\0';

					dot = strchr(dot+1, '.');
					uint8_t ip3_len = dot-ip-ip1_len-ip2_len-2;
					char ip3[ip3_len+1];
					memcpy(ip3, &ip[ip1_len+ip2_len+2], ip3_len);
					ip3[ip3_len] = '\0';

					dot = strchr(dot+1, '.');
					uint8_t ip4_len = dot-ip-ip1_len-ip2_len-ip3_len-3;
					char ip4[ip4_len+1];
					memcpy(ip4, &ip[ip1_len+ip2_len+ip3_len+3], ip4_len);
					ip4[ip4_len] = '\0';

					uint32_t ip1_num, ip2_num, ip3_num, ip4_num;
					sscanf(ip1, "%u", &ip1_num);
					sscanf(ip2, "%u", &ip2_num);
					sscanf(ip3, "%u", &ip3_num);
					sscanf(ip4, "%u", &ip4_num);
					ue_info_array[ue_count].ip = (((((ip4_num * 256) + ip3_num) * 256) + ip2_num) * 256) +ip1_num;
					//printf("%u\n", ue_info_array[ue_count].ip);
				}
				else if(strncmp(line, "upli", 4) == 0)
				{
					int teid_len = 0;
					for(uint32_t i = 11; i<len; i++){
						if(line[i] >= '0' && line[i] <= '9') teid_len++;
						else break;
					}
					char up_teid[teid_len+1];
					memcpy(up_teid, &line[11], teid_len);
					up_teid[teid_len] = '\0';
					//printf("%s.\n", up_teid);
					uint32_t ul_teid_num;
					sscanf(up_teid, "%u", &ul_teid_num);
					ue_info_array[ue_count].ul_teid = ul_teid_num;
				}
				else
				{
					int teid_len = 0;
					for(uint32_t i = 13; i<len; i++){
						if(line[i] >= '0' && line[i] <= '9') teid_len++;
						else break;
					}
					char down_teid[teid_len+1];
					memcpy(down_teid, &line[13], teid_len);
					down_teid[teid_len] = '\0';
					//printf("%s.\n", down_teid);
					uint32_t dl_teid_num;
					sscanf(down_teid, "%u", &dl_teid_num);
					ue_info_array[ue_count].dl_teid = dl_teid_num;
				}
			}
			fclose(f);
			if(line) free(line);
			ue_count++;
		}
	}
	for(uint32_t i=0; i<ue_count; i++){
		printf("ip=%u, ul=%u, dl=%u\n", ue_info_array[i].ip,
						                ue_info_array[i].ul_teid,
										ue_info_array[i].dl_teid);
	}
}

/* Custom handling of signals to handle stats and kni processing */
static void
signal_handler(int signum)
{
	/* When we receive a USR1 signal, print stats */
	if (signum == SIGUSR1) {
		print_stats();
		get_ue_info();
	}

	/* When we receive a USR2 signal, reset stats */
	if (signum == SIGUSR2) {
		//memset(&kni_stats, 0, sizeof(kni_stats));
		//printf("\n** Statistics have been reset **\n");
		struct rte_eth_stats stats[2];
		rte_eth_stats_get(0, &stats[0]);
		rte_eth_stats_get(1, &stats[1]);
		for(int i=0; i<2; i++) printf("Port %u\nipackets: %lu, opackets: %lu, ibytes: %lu, obytes: %lu, imissed: %lu, oerrors: %lu, rx_nombuf: %lu\n",
			  					i, stats[i].ipackets, stats[i].opackets, stats[i].ibytes, stats[i].obytes, stats[i].imissed,
								stats[i].oerrors, stats[i].rx_nombuf);
		return;
	}

	/*
	 * When we receive a RTMIN or SIGINT or SIGTERM signal,
	 * stop kni processing
	 */
	if (signum == SIGRTMIN || signum == SIGINT || signum == SIGTERM) {
		printf("\nSIGRTMIN/SIGINT/SIGTERM received. "
			"KNI processing stopping.\n");
		rte_atomic32_inc(&kni_stop);
		return;
        }
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

static __rte_always_inline void 
gtp_decap(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *outer_ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	gtpv1_t *gtp_hdr;
	// struct rte_ipv4_hdr *inner_ipv4_hdr;
	eth_hdr  = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	outer_ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	udp_hdr = (struct rte_udp_hdr *)(outer_ipv4_hdr + 1);
	gtp_hdr = (gtpv1_t *)(udp_hdr + 1);
	// inner_ipv4_hdr = (struct rte_ipv4_hdr *)(gtp_hdr + 1);

	int idx = -1;
	for(int i=0; i<64; i++){
		if(rte_cpu_to_be_32(ue_info_array[i].dl_teid) == gtp_hdr->teid){
			//printf("GTP Decap UE found, TEID: %u\n", gtp_hdr->teid);
			idx = i;
			break;
		}
	}
	if(idx == -1) {
		//printf("GTP Decap UE not found.\n");
		return;
	}
	
	const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
							  sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t) + 0;
	rte_pktmbuf_adj(m, (uint16_t) outer_hdr_len);
	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(struct rte_ether_hdr));
	eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	//eth_hdr->s_addr.addr_bytes[0] = (uint8_t)0x3c;
	//eth_hdr->s_addr.addr_bytes[1] = (uint8_t)0xfd;
	//eth_hdr->s_addr.addr_bytes[2] = (uint8_t)0xfe;
	//eth_hdr->s_addr.addr_bytes[3] = (uint8_t)0xba;
	//eth_hdr->s_addr.addr_bytes[4] = (uint8_t)0xf2;
	//eth_hdr->s_addr.addr_bytes[5] = (uint8_t)0x21;
	eth_hdr->s_addr.addr_bytes[0] = (uint8_t)mac_agf_to_rg[0];
	eth_hdr->s_addr.addr_bytes[1] = (uint8_t)mac_agf_to_rg[1];
	eth_hdr->s_addr.addr_bytes[2] = (uint8_t)mac_agf_to_rg[2];
	eth_hdr->s_addr.addr_bytes[3] = (uint8_t)mac_agf_to_rg[3];
	eth_hdr->s_addr.addr_bytes[4] = (uint8_t)mac_agf_to_rg[4];
	eth_hdr->s_addr.addr_bytes[5] = (uint8_t)mac_agf_to_rg[5];
	eth_hdr->d_addr.addr_bytes[0] = ue_info_array[idx].mac[0];
	eth_hdr->d_addr.addr_bytes[1] = ue_info_array[idx].mac[1];
	eth_hdr->d_addr.addr_bytes[2] = ue_info_array[idx].mac[2];
	eth_hdr->d_addr.addr_bytes[3] = ue_info_array[idx].mac[3];
	eth_hdr->d_addr.addr_bytes[4] = ue_info_array[idx].mac[4];
	eth_hdr->d_addr.addr_bytes[5] = ue_info_array[idx].mac[5];
}

static __rte_always_inline void
gtp_encap(struct rte_mbuf *m, uint32_t ip)
{
	int idx = -1;

	//Remove Ethernet header
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
    
	//Create Outer header
	const int outer_hdr_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + 
							  sizeof(struct rte_udp_hdr) + sizeof(gtpv1_t);
	//m = (struct rte_mbuf *) rte_pktmbuf_prepend(m, (uint16_t)outer_hdr_len);
	//rte_prefetch0(rte_pktmbuf_mtod(m, void *));
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, (uint16_t)outer_hdr_len);
	//struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
	struct rte_udp_hdr *udp_hdr= (struct rte_udp_hdr *)(ipv4_hdr + 1);
	gtpv1_t *gtp_hdr = (gtpv1_t *)(udp_hdr + 1);

	for(int i=0; i<64; i++){
		if(ue_info_array[i].ip == ip){
			//printf("GTP Encap UE found. Array:%u, Pkt:%u.\n", ue_info_array[i].ip, ip);
			idx = i;
			break;
		}
	}
	
	if(unlikely(idx == -1)) {
		//printf("GTP Encap UE not found.\n");
		return;
	}

	//Ethernet header
	/*struct rte_ether_addr src_mac, dst_mac;
	src_mac.addr_bytes[0] = (uint8_t)0x2c;
	src_mac.addr_bytes[1] = (uint8_t)0x60;
	src_mac.addr_bytes[2] = (uint8_t)0x0c;
	src_mac.addr_bytes[3] = (uint8_t)0xca;
	src_mac.addr_bytes[4] = (uint8_t)0x58;
	src_mac.addr_bytes[5] = (uint8_t)0x28;

	dst_mac.addr_bytes[0] = (uint8_t)0xd8;
	dst_mac.addr_bytes[1] = (uint8_t)0xc4;
	dst_mac.addr_bytes[2] = (uint8_t)0x97;
	dst_mac.addr_bytes[3] = (uint8_t)0x79;
	dst_mac.addr_bytes[4] = (uint8_t)0x87;
	dst_mac.addr_bytes[5] = (uint8_t)0xb2;*/
	eth_hdr->ether_type = 0x8;
	rte_ether_addr_copy(&agf_uplink_mac, &(eth_hdr->s_addr));
	rte_ether_addr_copy(&core_downlink_mac, &(eth_hdr->d_addr));

	//IPv4 header
	ipv4_hdr->version_ihl = RTE_IPV4_VHL_DEF;
	ipv4_hdr->total_length = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr));
	ipv4_hdr->time_to_live = IPDEFTTL;
	ipv4_hdr->next_proto_id = IPPROTO_UDP;
	//ipv4_hdr->src_addr = rte_cpu_to_be_32((uint32_t)174351362);
	//ipv4_hdr->dst_addr = rte_cpu_to_be_32((uint32_t)174351370);
	ipv4_hdr->src_addr = rte_cpu_to_be_32((uint32_t)ip_agf_to_5gc);
	ipv4_hdr->dst_addr = rte_cpu_to_be_32((uint32_t)ip_5gc_to_agf);
	ipv4_hdr->hdr_checksum = 0;
	ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);

	//UDP header
	udp_hdr->src_port = 0x6808;
	udp_hdr->dst_port = 0x6808;
	udp_hdr->dgram_len = rte_cpu_to_be_16(m->pkt_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));
	udp_hdr->dgram_cksum = 0;

    //GTP header
	uint16_t payload_len = m->pkt_len - sizeof(struct rte_ether_hdr)
									  - sizeof(struct rte_ipv4_hdr)
									  - sizeof(struct rte_udp_hdr) - 8; //Probably need to fix?
	gtp_hdr->flags = 0x30;
	gtp_hdr->type = 255;
	gtp_hdr->length = rte_cpu_to_be_16(payload_len);
	gtp_hdr->teid = rte_cpu_to_be_32((uint32_t)ue_info_array[idx].ul_teid);

	//Checksum offloads
	//m->l2_len = sizeof(struct rte_ether_hdr);
	//m->l3_len = sizeof(struct rte_ipv4_hdr);
	//m->ol_flags |= PKT_TX_IPV4 | PKT_TX_IP_CKSUM;
}

/*
static void
basic_dl(struct kni_port_params *p)
{
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	unsigned nb_rx, nb_tx;
	uint16_t port_id = p->port_id;
	nb_rx = rte_eth_rx_burst(port_id, 0, pkts_burst, PKT_BURST_SZ);
	if (unlikely(nb_rx == 0)) return;
	
	nb_tx = 0;
	for (unsigned i = 0; i < nb_rx; i++){
		struct rte_mbuf *m;
		m = pkts_burst[i];
		
		rte_prefetch0(rte_pktmbuf_mtod(m, void *));
		struct rte_ether_hdr *eth_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_udp_hdr *udp_hdr;
		eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
		udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1 );
		//uint16_t d_port = 0;
		//if (ipv4_hdr->next_proto_id == 17) d_port = rte_be_to_cpu_16(udp_hdr->dst_port);
		if (eth_hdr->ether_type != 1544)
		{
			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		}

		nb_tx += rte_eth_tx_burst(port_id^1, 0, &m, 1);
	}
	
	// nb_tx = rte_eth_tx_burst(port_id^1, 0, pkts_burst, nb_rx);
	for(unsigned i=0; i < p->nb_kni; i++){
		for(int j=0; j<1000000; j++){
			int k = j;
			j += 1;
			j = k;
		}
		rte_kni_handle_request(p->kni[i]);
	}
	if (unlikely(nb_tx < nb_rx))
	{
		uint16_t buf;
		for(buf = nb_tx; buf < nb_rx; buf++)
		{
			rte_pktmbuf_free(pkts_burst[buf]);
		}
	}
}
*/
/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
static void
kni_handle_loop(struct kni_port_params *p)
{
	uint8_t i;
	uint32_t nb_kni;
	nb_kni = p->nb_kni;
	for(i = 0; i < nb_kni; i++) {
		rte_kni_handle_request(p->kni[i]);
	}
}

static void
kni_ingress_dl(struct kni_port_params *p, uint16_t qid)
{
	//printf("dl\n");
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *tx_eth_pkt[PKT_BURST_SZ];
	int tx_cnt;
	//static int cnt = 0;
	//cnt++;
	//if ((cnt % 30000000) == 5) printf("lcode ID = %d\n", rte_lcore_id());
	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	//port_id = (rte_lcore_id() / 2);
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, qid, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			printf("Ethernet receivin error.\n");
			return;
		}
		 
		num = 0;
		tx_cnt = 0;
		struct rte_mbuf *m;
		struct rte_ether_hdr *eth_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_udp_hdr *udp_hdr;
		uint16_t d_port;
		
		// if(nb_rx > 0) printf("port %u qid %u nb_rx: %u\n", port_id, qid, nb_rx);

		for(uint8_t j=0; j<nb_rx; j++){
			// printf("dl receive something\n");
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1 );
			d_port = 0;
			if (ipv4_hdr->next_proto_id == 17) d_port = rte_be_to_cpu_16(udp_hdr->dst_port);
			//printf("rss:%u\n", m->hash.rss);
			if (unlikely(eth_hdr->ether_type == 1544)) {
				struct rte_arp_hdr *arp_hdr;
				arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
				printf("Got ARP with opcode %u\n", arp_hdr->arp_opcode);

				// Learn
				for(int k=0; k<64; k++){
					if(ue_info_array[k].ip == arp_hdr->arp_data.arp_sip){
						ue_info_array[k].mac[0] = eth_hdr->s_addr.addr_bytes[0];
						ue_info_array[k].mac[1] = eth_hdr->s_addr.addr_bytes[1];
						ue_info_array[k].mac[2] = eth_hdr->s_addr.addr_bytes[2];
						ue_info_array[k].mac[3] = eth_hdr->s_addr.addr_bytes[3];
						ue_info_array[k].mac[4] = eth_hdr->s_addr.addr_bytes[4];
						ue_info_array[k].mac[5] = eth_hdr->s_addr.addr_bytes[5];
						break;
					}
				}

				switch(arp_hdr->arp_opcode){
					case RTE_BE16(RTE_ARP_OP_REQUEST):
						rte_ether_addr_copy(&(eth_hdr->s_addr), &(eth_hdr->d_addr));
						struct rte_ether_addr arp_src_mac;
						arp_src_mac.addr_bytes[0] = (uint8_t)0x3c;
						arp_src_mac.addr_bytes[1] = (uint8_t)0xfd;
						arp_src_mac.addr_bytes[2] = (uint8_t)0xfe;
						arp_src_mac.addr_bytes[3] = (uint8_t)0xba;
						arp_src_mac.addr_bytes[4] = (uint8_t)0xf2;
						arp_src_mac.addr_bytes[5] = (uint8_t)0x21;
						uint32_t tip = 4261428284;
						rte_ether_addr_copy(&(arp_src_mac), &(eth_hdr->s_addr));

						arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
						rte_memcpy(&(arp_hdr->arp_data.arp_tha), &(arp_hdr->arp_data.arp_sha), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_sha), &(arp_src_mac), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_tip), &(arp_hdr->arp_data.arp_sip), 4);
						rte_memcpy(&(arp_hdr->arp_data.arp_sip), &tip, 4);
			
						num += rte_eth_tx_burst(port_id, 0, &(pkts_burst[j]), 1);
						printf("ARP Request sent.\n");
						break;
					default:
						break;
				}
			}
			else if (unlikely(ipv4_hdr->next_proto_id == 17 && d_port == 67))
			{
				num += rte_kni_tx_burst(p->kni[i], &(pkts_burst[j]), 1);
			}
			else
			{
				gtp_encap(m, ipv4_hdr->src_addr);
				//num += rte_eth_tx_burst(port_id^1, 0, &(pkts_burst[j]), 1);
				tx_eth_pkt[tx_cnt++] = pkts_burst[j];
			}

		}
		if(tx_cnt > 0)
		{
			num += rte_eth_tx_burst(port_id^1, 0, tx_eth_pkt, tx_cnt);
		}
		//rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			printf("%u pkt(s) been drop at dl.\n", nb_rx - num);
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			// kni_stats[port_id].rx_dropped += nb_rx - num;
		}
	}
}

static void
kni_ingress_dl_gtp(struct kni_port_params *p, uint16_t qid)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *tx_eth_pkt[PKT_BURST_SZ];
	int tx_cnt;
	
	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	//port_id = (rte_lcore_id() / 2);
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, qid, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			printf("Ethernet receivin error.\n");
			return;
		}
		 
		num = 0;
		tx_cnt = 0;
		struct rte_mbuf *m;
		struct rte_ether_hdr *eth_hdr;
		struct rte_ipv4_hdr *ipv4_hdr;
		struct rte_udp_hdr *udp_hdr;
		
		if(nb_rx > 0) printf("port %u nb_rx: %u\n", port_id, nb_rx);
		
		for(uint8_t j=0; j<nb_rx; j++){
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1 );
			uint16_t d_port = 0;
			if (ipv4_hdr->next_proto_id == 17) d_port = rte_be_to_cpu_16(udp_hdr->dst_port);

			if(unlikely(eth_hdr->ether_type == 1544)){
				struct rte_arp_hdr *arp_hdr;
				arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
				printf("Got ARP with opcode %u\n", arp_hdr->arp_opcode);

				// Learn
				for(int k=0; k<64; k++){
					if(ue_info_array[k].ip == arp_hdr->arp_data.arp_sip){
						ue_info_array[k].mac[0] = eth_hdr->s_addr.addr_bytes[0];
						ue_info_array[k].mac[1] = eth_hdr->s_addr.addr_bytes[1];
						ue_info_array[k].mac[2] = eth_hdr->s_addr.addr_bytes[2];
						ue_info_array[k].mac[3] = eth_hdr->s_addr.addr_bytes[3];
						ue_info_array[k].mac[4] = eth_hdr->s_addr.addr_bytes[4];
						ue_info_array[k].mac[5] = eth_hdr->s_addr.addr_bytes[5];
						break;
					}
				}

				switch(arp_hdr->arp_opcode){
					case RTE_BE16(RTE_ARP_OP_REQUEST):
						rte_ether_addr_copy(&(eth_hdr->s_addr), &(eth_hdr->d_addr));
						struct rte_ether_addr arp_src_mac;
						arp_src_mac.addr_bytes[0] = (uint8_t)0x3c;
						arp_src_mac.addr_bytes[1] = (uint8_t)0xfd;
						arp_src_mac.addr_bytes[2] = (uint8_t)0xfe;
						arp_src_mac.addr_bytes[3] = (uint8_t)0xba;
						arp_src_mac.addr_bytes[4] = (uint8_t)0xf2;
						arp_src_mac.addr_bytes[5] = (uint8_t)0x21;
						uint32_t tip = 4261428284;
						rte_ether_addr_copy(&(arp_src_mac), &(eth_hdr->s_addr));

						arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
						rte_memcpy(&(arp_hdr->arp_data.arp_tha), &(arp_hdr->arp_data.arp_sha), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_sha), &(arp_src_mac), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_tip), &(arp_hdr->arp_data.arp_sip), 4);
						rte_memcpy(&(arp_hdr->arp_data.arp_sip), &tip, 4);
			
						num += rte_eth_tx_burst(port_id, 0, &(pkts_burst[j]), 1);
						printf("ARP Request sent.\n");
						break;
					default:
						break;
				}
			}
			else if(unlikely(ipv4_hdr->next_proto_id == 17 && d_port == 67))
			{
				num += rte_kni_tx_burst(p->kni[i], &(pkts_burst[j]), 1);
			}
			else
			{
				gtp_encap(m, ipv4_hdr->src_addr);
				//num += rte_eth_tx_burst(port_id^1, 0, &(pkts_burst[j]), 1);
				tx_eth_pkt[tx_cnt++] = pkts_burst[j];


			}

		}
		if(tx_cnt > 0)
		{
			num += rte_eth_tx_burst(port_id^1, 0, tx_eth_pkt, tx_cnt);
		}
		//rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			printf("%u pkt(s) been drop at dl.\n", nb_rx - num);
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			// kni_stats[port_id].rx_dropped += nb_rx - num;
		}
	}
}
		

static void
kni_ingress_ul(struct kni_port_params *p, uint16_t qid)
{
	//printf("ul\n");
	uint8_t i;
	uint16_t port_id;
	unsigned nb_rx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];
	struct rte_mbuf *tx_eth_pkts[PKT_BURST_SZ];
	int tx_cnt;
	if (p == NULL)
		return;
	//static int cnt = 0;
	//cnt++;
	//if ((cnt % 30000000) == 5) printf("lcode ID = %d\n", rte_lcore_id());

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	port_id = (rte_lcore_id() / 2);
	//printf("1\n");
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from eth */
		nb_rx = rte_eth_rx_burst(port_id, qid, pkts_burst, PKT_BURST_SZ);
		if (unlikely(nb_rx > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from eth\n");
			return;
		}
		// if(nb_rx > 0)printf("port %u qid %u nb_rx:%u\n", port_id, qid, nb_rx); 
		num = 0;
		tx_cnt = 0;		
		struct rte_mbuf *m;
		for(uint8_t j=0; j<nb_rx; j++){
			// printf("KNI ingress received something.\n");
			// printf("lcore_id:%u\n", rte_lcore_id());
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			struct rte_ether_hdr *eth_hdr;
			struct rte_ipv4_hdr *ipv4_hdr;
			struct rte_udp_hdr *udp_hdr;
			eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
			udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1 );
			uint16_t d_port = 0;
			if (ipv4_hdr->next_proto_id == 17) d_port = rte_be_to_cpu_16(udp_hdr->dst_port);

			if(unlikely(eth_hdr->ether_type == 1544)){
				struct rte_arp_hdr *arp_hdr;
				arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
				printf("Got ARP with opcode %u\n", arp_hdr->arp_opcode);
				switch(arp_hdr->arp_opcode){
					case RTE_BE16(RTE_ARP_OP_REQUEST):
						rte_ether_addr_copy(&(eth_hdr->s_addr), &(eth_hdr->d_addr));
						struct rte_ether_addr arp_src_mac;
						arp_src_mac.addr_bytes[0] = (uint8_t)0x3c;
						arp_src_mac.addr_bytes[1] = (uint8_t)0xfd;
						arp_src_mac.addr_bytes[2] = (uint8_t)0xfe;
						arp_src_mac.addr_bytes[3] = (uint8_t)0xba;
						arp_src_mac.addr_bytes[4] = (uint8_t)0xf2;
						arp_src_mac.addr_bytes[5] = (uint8_t)0x20;
						uint32_t tip = 40133642;
						rte_ether_addr_copy(&(arp_src_mac), &(eth_hdr->s_addr));

						arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
						rte_memcpy(&(arp_hdr->arp_data.arp_tha), &(arp_hdr->arp_data.arp_sha), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_sha), &(arp_src_mac), RTE_ETHER_ADDR_LEN);
						rte_memcpy(&(arp_hdr->arp_data.arp_tip), &(arp_hdr->arp_data.arp_sip), 4);
						rte_memcpy(&(arp_hdr->arp_data.arp_sip), &tip, 4);
						num += rte_eth_tx_burst(port_id, 0, &(pkts_burst[j]), 1);
						printf("ARP Request sent.\n");
						break;
					default:
						break;
				}
			}
			else if(ipv4_hdr->next_proto_id == 17 && d_port == 2152)
			{
				gtp_decap(m);
				tx_eth_pkts[tx_cnt++] = pkts_burst[j];
				//num += rte_eth_tx_burst(port_id^1, 0, &(pkts_burst[j]), 1);
			}
			else
			{
				//printf("ul ip proto: %u\n", ipv4_hdr->next_proto_id);
				num += rte_kni_tx_burst(p->kni[i], &(pkts_burst[j]), 1);
			}
		}
		num += rte_eth_tx_burst(port_id^1, 0, tx_eth_pkts, (uint16_t) tx_cnt);
		
		/* Burst tx to kni */
		// num = rte_kni_tx_burst(p->kni[i], pkts_burst, nb_rx);
		// if (num) kni_stats[port_id].rx_packets += num;
		
		//rte_kni_handle_request(p->kni[i]);
		if (unlikely(num < nb_rx)) {
			/* Free mbufs not tx to kni interface */
			kni_burst_free_mbufs(&pkts_burst[num], nb_rx - num);
			// kni_stats[port_id].rx_dropped += nb_rx - num;
			printf("%u pkt(s) been drop at ul.\n", nb_rx - num);
		}
	}
}


/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
static void
kni_egress(struct kni_port_params *p)
{
	uint8_t i;
	uint16_t port_id;
	unsigned nb_tx, num;
	uint32_t nb_kni;
	struct rte_mbuf *pkts_burst[PKT_BURST_SZ];

	if (p == NULL)
		return;

	nb_kni = p->nb_kni;
	port_id = p->port_id;
	for (i = 0; i < nb_kni; i++) {
		/* Burst rx from kni */
		num = rte_kni_rx_burst(p->kni[i], pkts_burst, PKT_BURST_SZ);
		if (unlikely(num > PKT_BURST_SZ)) {
			RTE_LOG(ERR, APP, "Error receiving from KNI\n");
			return;
		}
		/* Burst tx to eth */
		nb_tx = rte_eth_tx_burst(port_id, 0, pkts_burst, (uint16_t)num);
		if (nb_tx)
		{
			kni_stats[port_id].tx_packets += nb_tx;
			printf("Egress %d sent something.\n", port_id);
		}
		if (unlikely(nb_tx < num)) {
			/* Free mbufs not tx to NIC */
			kni_burst_free_mbufs(&pkts_burst[nb_tx], num - nb_tx);
			kni_stats[port_id].tx_dropped += num - nb_tx;
		}
		rte_kni_handle_request(p->kni[i]);
	}
}

static int
main_loop(__rte_unused void *arg)
{
	uint16_t i;
	int32_t f_stop;
	int32_t f_pause;
	const unsigned lcore_id = rte_lcore_id();
	enum lcore_rxtx {
		LCORE_NONE,
		LCORE_RX,
		LCORE_TX,
		LCORE_MAX
	};
	enum lcore_rxtx flag = LCORE_NONE;

	RTE_ETH_FOREACH_DEV(i) {
		if (!kni_port_params_array[i])
			continue;
		if (kni_port_params_array[i]->lcore_rx == (uint8_t)lcore_id) {
			flag = LCORE_RX;
			break;
		} else if (kni_port_params_array[i]->lcore_tx ==
						(uint8_t)lcore_id) {
			flag = LCORE_TX;
			break;
		}
	}

	i = (lcore_id / 4);
	if(i > 0) i = 1; 
	if (flag == LCORE_RX) {
		RTE_LOG(INFO, APP, "Lcore %u is reading from port %d\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);
		while (1) {
			
			f_stop = rte_atomic32_read(&kni_stop);
			f_pause = rte_atomic32_read(&kni_pause);
			if (f_stop)
				break;
			if (f_pause)
				continue;
			//basic_dl(kni_port_params_array[i]);
			if (kni_port_params_array[i]->port_id == 0) kni_ingress_ul(kni_port_params_array[i], 0);
			else kni_ingress_dl(kni_port_params_array[i], 0);
			//kni_ingress(kni_port_param_array[i]);
		}
	} else if (flag == LCORE_TX) {
		RTE_LOG(INFO, APP, "Lcore %u is writing to port %d\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);
		while (1) {
			
			f_stop = rte_atomic32_read(&kni_stop);
			f_pause = rte_atomic32_read(&kni_pause);
			if (f_stop)
				break;
			if (f_pause)
				continue;
			
			kni_egress(kni_port_params_array[i]);
		}
	} else
	{
		/*if(lcore_id == 2 || lcore_id == 6){
			
			while (1) {
				f_stop = rte_atomic32_read(&kni_stop);
				f_pause = rte_atomic32_read(&kni_pause);
				if (f_stop)
					break;
				if (f_pause)
					continue;
				if (kni_port_params_array[i]->port_id == 0) kni_ingress_ul(kni_port_params_array[i], 0);
				else kni_ingress_dl(kni_port_params_array[i], 0);
				//kni_ingress_dl(kni_port_params_array[i], 1);
			}
			
			//if(lcore_id == 2)kni_inress_ul(kni_port_params_array[i], 0);
			//else kni_ingress_ul(kni_port_params_array[i], 1)
		}*/
		RTE_LOG(INFO, APP, "Lcore %u has nothing to do\n", lcore_id);
	}
	return 0;
}

/* Display usage instructions */
static void
print_usage(const char *prgname)
{
	RTE_LOG(INFO, APP, "\nUsage: %s [EAL options] -- -p PORTMASK -P -m "
		   "[--config (port,lcore_rx,lcore_tx,lcore_kthread...)"
		   "[,(port,lcore_rx,lcore_tx,lcore_kthread...)]]\n"
		   "    -p PORTMASK: hex bitmask of ports to use\n"
		   "    -P : enable promiscuous mode\n"
		   "    -m : enable monitoring of port carrier state\n"
		   "    --config (port,lcore_rx,lcore_tx,lcore_kthread...): "
		   "port and lcore configurations\n",
	           prgname);
}

/* Convert string to unsigned number. 0 is returned if error occurs */
static uint32_t
parse_unsigned(const char *portmask)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return (uint32_t)num;
}

static void
print_config(void)
{
	uint32_t i, j;
	struct kni_port_params **p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, APP, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, APP, "Rx lcore ID: %u, Tx lcore ID: %u\n",
					p[i]->lcore_rx, p[i]->lcore_tx);
		for (j = 0; j < p[i]->nb_lcore_k; j++)
			RTE_LOG(DEBUG, APP, "Kernel thread lcore ID: %u\n",
							p[i]->lcore_k[j]);
	}
}

static int
parse_config(const char *arg)
{
	const char *p, *p0 = arg;
	char s[256], *end;
	unsigned size;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_LCORE_RX,
		FLD_LCORE_TX,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, j, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];
	uint16_t port_id, nb_kni_port_params = 0;

	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
	while (((p = strchr(p0, '(')) != NULL) &&
		nb_kni_port_params < RTE_MAX_ETHPORTS) {
		p++;
		if ((p0 = strchr(p, ')')) == NULL)
			goto fail;
		size = p0 - p;
		if (size >= sizeof(s)) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		snprintf(s, sizeof(s), "%.*s", size, p);
		nb_token = rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',');
		if (nb_token <= FLD_LCORE_TX) {
			printf("Invalid config parameters\n");
			goto fail;
		}
		for (i = 0; i < nb_token; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i]) {
				printf("Invalid config parameters\n");
				goto fail;
			}
		}

		i = 0;
		port_id = int_fld[i++];
		if (port_id >= RTE_MAX_ETHPORTS) {
			printf("Port ID %d could not exceed the maximum %d\n",
						port_id, RTE_MAX_ETHPORTS);
			goto fail;
		}
		if (kni_port_params_array[port_id]) {
			printf("Port %d has been configured\n", port_id);
			goto fail;
		}
		kni_port_params_array[port_id] =
			rte_zmalloc("KNI_port_params",
				    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
		kni_port_params_array[port_id]->port_id = port_id;
		kni_port_params_array[port_id]->lcore_rx =
					(uint8_t)int_fld[i++];
		kni_port_params_array[port_id]->lcore_tx =
					(uint8_t)int_fld[i++];
		if (kni_port_params_array[port_id]->lcore_rx >= RTE_MAX_LCORE ||
		kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
			printf("lcore_rx %u or lcore_tx %u ID could not "
						"exceed the maximum %u\n",
				kni_port_params_array[port_id]->lcore_rx,
				kni_port_params_array[port_id]->lcore_tx,
						(unsigned)RTE_MAX_LCORE);
			goto fail;
		}
		for (j = 0; i < nb_token && j < KNI_MAX_KTHREAD; i++, j++)
			kni_port_params_array[port_id]->lcore_k[j] =
						(uint8_t)int_fld[i];
		kni_port_params_array[port_id]->nb_lcore_k = j;
	}
	print_config();

	return 0;

fail:
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}
	}

	return -1;
}

static int
validate_parameters(uint32_t portmask)
{
	uint32_t i;

	if (!portmask) {
		printf("No port configured in port mask\n");
		return -1;
	}

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (((portmask & (1 << i)) && !kni_port_params_array[i]) ||
			(!(portmask & (1 << i)) && kni_port_params_array[i]))
			rte_exit(EXIT_FAILURE, "portmask is not consistent "
				"to port ids specified in --config\n");

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_rx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d receiving not enabled\n",
					kni_port_params_array[i]->lcore_rx,
					kni_port_params_array[i]->port_id);

		if (kni_port_params_array[i] && !rte_lcore_is_enabled(\
			(unsigned)(kni_port_params_array[i]->lcore_tx)))
			rte_exit(EXIT_FAILURE, "lcore id %u for "
					"port %d transmitting not enabled\n",
					kni_port_params_array[i]->lcore_tx,
					kni_port_params_array[i]->port_id);

	}

	return 0;
}

#define CMDLINE_OPT_CONFIG  "config"

/* Parse the arguments given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, longindex, ret = 0;
	const char *prgname = argv[0];
	static struct option longopts[] = {
		{CMDLINE_OPT_CONFIG, required_argument, NULL, 0},
		{NULL, 0, NULL, 0}
	};

	/* Disable printing messages within getopt() */
	opterr = 0;

	/* Parse command line */
	while ((opt = getopt_long(argc, argv, "p:Pm", longopts,
						&longindex)) != EOF) {
		switch (opt) {
		case 'p':
			ports_mask = parse_unsigned(optarg);
			break;
		case 'P':
			promiscuous_on = 1;
			break;
		case 'm':
			monitor_links = 1;
			break;
		case 0:
			if (!strncmp(longopts[longindex].name,
				     CMDLINE_OPT_CONFIG,
				     sizeof(CMDLINE_OPT_CONFIG))) {
				ret = parse_config(optarg);
				if (ret) {
					printf("Invalid config\n");
					print_usage(prgname);
					return -1;
				}
			}
			break;
		default:
			print_usage(prgname);
			rte_exit(EXIT_FAILURE, "Invalid option specified\n");
		}
	}

	/* Check that options were parsed ok */
	if (validate_parameters(ports_mask) < 0) {
		print_usage(prgname);
		rte_exit(EXIT_FAILURE, "Invalid parameters\n");
	}

	return ret;
}

/* Initialize KNI subsystem */
static void
init_kni(void)
{
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

	/* Calculate the maximum number of KNI interfaces that will be used */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			num_of_kni_ports += (params[i]->nb_lcore_k ?
				params[i]->nb_lcore_k : 1);
		}
	}

	/* Invoke rte KNI init to preallocate the ports */
	rte_kni_init(num_of_kni_ports);
}

/* Initialise a single port on an Ethernet device */
static void
init_port(uint16_t port)
{
	int ret;
	uint16_t nb_rxd = NB_RXD;
	uint16_t nb_txd = NB_TXD;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf, rxq_conf2;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_conf local_port_conf = port_conf;

	/* Initialise device and RX/TX queues */
	RTE_LOG(INFO, APP, "Initialising port %u ...\n", (unsigned)port);
	fflush(stdout);

	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port, strerror(-ret));

	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	/*if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM)
	{
		local_port_conf.txmode.offloads |=
		DEV_TX_OFFLOAD_IPV4_CKSUM;
		printf("TX OFFLOAD IPV4 CKSUM\n");
	}	
	
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM)
		local_port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_UDP_CKSUM;
	*/
	printf("port %u tx offload=%lu\n", port, dev_info.tx_offload_capa);
	printf("port %u max_rx_queue=%u\n", port, dev_info.max_rx_queues);
	ret = rte_eth_dev_configure(port, 1, 1, &local_port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not configure port%u (%d)\n",
		            (unsigned)port, ret);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned)port, ret);

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = local_port_conf.rxmode.offloads;
	//rxq_conf2 = dev_info.default_rxconf;
	//rxq_conf2.offloads = local_port_conf.rxmode.offloads;
	
	ret = rte_eth_rx_queue_setup(port, 0, nb_rxd,
		rte_eth_dev_socket_id(port), &rxq_conf, pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				"port%u (%d)\n", (unsigned)port, ret);
	
	/*ret = rte_eth_rx_queue_setup(port, 1, nb_rxd,
		rte_eth_dev_socket_id(port), &rxq_conf2, pktmbuf_pool);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up RX queue for "
				"port%u (%d)\n", (unsigned)port, ret);
	*/
	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = local_port_conf.txmode.offloads;
	//txq_conf.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
	//txq_conf.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
	ret = rte_eth_tx_queue_setup(port, 0, nb_txd,
		rte_eth_dev_socket_id(port), &txq_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not setup up TX queue for "
				"port%u (%d)\n", (unsigned)port, ret);

	ret = rte_eth_dev_start(port);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not start port%u (%d)\n",
						(unsigned)port, ret);

	if (promiscuous_on) {
		ret = rte_eth_promiscuous_enable(port);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Could not enable promiscuous mode for port%u: %s\n",
				port, rte_strerror(-ret));
	}
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

	printf("\nChecking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
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

static void
log_link_state(struct rte_kni *kni, int prev, struct rte_eth_link *link)
{
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	if (kni == NULL || link == NULL)
		return;

	rte_eth_link_to_str(link_status_text, sizeof(link_status_text), link);
	if (prev != link->link_status)
		RTE_LOG(INFO, APP, "%s NIC %s",
			rte_kni_get_name(kni),
			link_status_text);
}

/*
 * Monitor the link status of all ports and update the
 * corresponding KNI interface(s)
 */
static void *
monitor_all_ports_link_status(void *arg)
{
	uint16_t portid;
	struct rte_eth_link link;
	unsigned int i;
	struct kni_port_params **p = kni_port_params_array;
	int prev;
	(void) arg;
	int ret;

	while (monitor_links) {
		rte_delay_ms(500);
		RTE_ETH_FOREACH_DEV(portid) {
			if ((ports_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				RTE_LOG(ERR, APP,
					"Get link failed (port %u): %s\n",
					portid, rte_strerror(-ret));
				continue;
			}
			for (i = 0; i < p[portid]->nb_kni; i++) {
				prev = rte_kni_update_link(p[portid]->kni[i],
						link.link_status);
				log_link_state(p[portid]->kni[i], prev, &link);
			}
		}
	}
	return NULL;
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

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	ret = rte_eth_dev_stop(port_id);
	if (ret != 0) {
		RTE_LOG(ERR, APP, "Failed to stop port %d: %s\n",
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
		RTE_LOG(ERR, APP, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not adjust number of descriptors "
				"for port%u (%d)\n", (unsigned int)port_id,
				ret);

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0) {
		RTE_LOG(ERR, APP,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

		return ret;
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = conf.rxmode.offloads;
	ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
		rte_eth_dev_socket_id(port_id), &rxq_conf, pktmbuf_pool);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Rx queue of port %d\n",
				port_id);
		return ret;
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
		rte_eth_dev_socket_id(port_id), &txq_conf);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to setup Tx queue of port %d\n",
				port_id);
		return ret;
	}

	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(ERR, APP, "Fail to restart port %d\n", port_id);
		return ret;
	}

	return 0;
}

/* Callback for request of changing MTU */
static int
kni_change_mtu(uint16_t port_id, unsigned int new_mtu)
{
	int ret;

	rte_atomic32_inc(&kni_pause);
	ret =  kni_change_mtu_(port_id, new_mtu);
	rte_atomic32_dec(&kni_pause);

	return ret;
}

/* Callback for request of configuring network interface up/down */
static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure network interface of %d %s\n",
					port_id, if_up ? "up" : "down");

	rte_atomic32_inc(&kni_pause);

	if (if_up != 0) { /* Configure network interface up */
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0) {
			RTE_LOG(ERR, APP, "Failed to stop port %d: %s\n",
				port_id, rte_strerror(-ret));
			rte_atomic32_dec(&kni_pause);
			return ret;
		}
		ret = rte_eth_dev_start(port_id);
	} else { /* Configure network interface down */
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0) {
			RTE_LOG(ERR, APP, "Failed to stop port %d: %s\n",
				port_id, rte_strerror(-ret));
			rte_atomic32_dec(&kni_pause);
			return ret;
		}
	}

	rte_atomic32_dec(&kni_pause);

	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to start port %d\n", port_id);

	return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
	RTE_LOG(INFO, APP, "\t%s%s\n", name, buf);
}

/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
	int ret = 0;

	if (!rte_eth_dev_is_valid_port(port_id)) {
		RTE_LOG(ERR, APP, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}

	RTE_LOG(INFO, APP, "Configure mac address of %d\n", port_id);
	print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

	ret = rte_eth_dev_default_mac_addr_set(port_id,
					(struct rte_ether_addr *)mac_addr);
	if (ret < 0)
		RTE_LOG(ERR, APP, "Failed to config mac_addr for port %d\n",
			port_id);

	return ret;
}

static int
kni_alloc(uint16_t port_id)
{
	uint8_t i;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
	struct kni_port_params **params = kni_port_params_array;
	int ret;

	if (port_id >= RTE_MAX_ETHPORTS || !params[port_id])
		return -1;

	params[port_id]->nb_kni = params[port_id]->nb_lcore_k ?
				params[port_id]->nb_lcore_k : 1;

	for (i = 0; i < params[port_id]->nb_kni; i++) {
		/* Clear conf at first */
		memset(&conf, 0, sizeof(conf));
		if (params[port_id]->nb_lcore_k) {
			snprintf(conf.name, RTE_KNI_NAMESIZE,
					"vEth%u_%u", port_id, i);
			conf.core_id = params[port_id]->lcore_k[i];
			conf.force_bind = 1;
		} else
			snprintf(conf.name, RTE_KNI_NAMESIZE,
						"vEth%u", port_id);
		conf.group_id = port_id;
		conf.mbuf_size = MAX_PACKET_SZ;
		/*
		 * The first KNI device associated to a port
		 * is the main, for multiple kernel thread
		 * environment.
		 */
		if (i == 0) {
			struct rte_kni_ops ops;
			struct rte_eth_dev_info dev_info;

			ret = rte_eth_dev_info_get(port_id, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

			/* Get the interface default mac address */
			ret = rte_eth_macaddr_get(port_id,
				(struct rte_ether_addr *)&conf.mac_addr);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Failed to get MAC address (port %u): %s\n",
					port_id, rte_strerror(-ret));

			rte_eth_dev_get_mtu(port_id, &conf.mtu);

			conf.min_mtu = dev_info.min_mtu;
			conf.max_mtu = dev_info.max_mtu;

			memset(&ops, 0, sizeof(ops));
			ops.port_id = port_id;
			ops.change_mtu = kni_change_mtu;
			ops.config_network_if = kni_config_network_interface;
			ops.config_mac_address = kni_config_mac_address;

			kni = rte_kni_alloc(pktmbuf_pool, &conf, &ops);
		} else
			kni = rte_kni_alloc(pktmbuf_pool, &conf, NULL);

		if (!kni)
			rte_exit(EXIT_FAILURE, "Fail to create kni for "
						"port: %d\n", port_id);
		params[port_id]->kni[i] = kni;
	}

	return 0;
}

static int
kni_free_kni(uint16_t port_id)
{
	uint8_t i;
	int ret;
	struct kni_port_params **p = kni_port_params_array;

	if (port_id >= RTE_MAX_ETHPORTS || !p[port_id])
		return -1;

	for (i = 0; i < p[port_id]->nb_kni; i++) {
		if (rte_kni_release(p[port_id]->kni[i]))
			printf("Fail to release kni\n");
		p[port_id]->kni[i] = NULL;
	}
	ret = rte_eth_dev_stop(port_id);
	if (ret != 0)
		RTE_LOG(ERR, APP, "Failed to stop port %d: %s\n",
			port_id, rte_strerror(-ret));

	return 0;
}

/* Initialise ports/queues etc. and start main loop on each core */
int
main(int argc, char** argv)
{
	int ret;
	uint16_t nb_sys_ports, port;
	unsigned i;
	void *retval;
	pthread_t kni_link_tid;
	int pid;

	/* Associate signal_hanlder function with USR signals */
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGRTMIN, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Initialise EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not initialise EAL (%d)\n", ret);
	argc -= ret;
	argv += ret;

	/* Parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Could not parse input parameters\n");

	/* Get number of ports found in scan */
	nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0)
		rte_exit(EXIT_FAILURE, "No supported Ethernet device found\n");

	/* Create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF * nb_sys_ports,
		MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, rte_socket_id());
	if (pktmbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
		return -1;
	}


	/* Check if the configured port ID is valid */
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i] && !rte_eth_dev_is_valid_port(i))
			rte_exit(EXIT_FAILURE, "Configured invalid "
						"port ID %u\n", i);

	
	/* Initialize KNI subsystem */
	init_kni();

	/* Read network configuration */
	agf_uplink_mac.addr_bytes[0] = (uint8_t)0x3c;
	agf_uplink_mac.addr_bytes[1] = (uint8_t)0xfd;
	agf_uplink_mac.addr_bytes[2] = (uint8_t)0xfe;
	agf_uplink_mac.addr_bytes[3] = (uint8_t)0xba;
	agf_uplink_mac.addr_bytes[4] = (uint8_t)0xf2;
	agf_uplink_mac.addr_bytes[5] = (uint8_t)0x21;

	core_downlink_mac.addr_bytes[0] = (uint8_t)0x66;
	core_downlink_mac.addr_bytes[1] = (uint8_t)0x55;
	core_downlink_mac.addr_bytes[2] = (uint8_t)0x44;
	core_downlink_mac.addr_bytes[3] = (uint8_t)0x33;
	core_downlink_mac.addr_bytes[4] = (uint8_t)0x22;
	core_downlink_mac.addr_bytes[5] = (uint8_t)0x11;


	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(port) {
		/* Skip ports that are not enabled */
		if (!(ports_mask & (1 << port)))
			continue;
		init_port(port);

		if (port >= RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "Can not use more than "
				"%d ports for kni\n", RTE_MAX_ETHPORTS);

		kni_alloc(port);
	}
	check_all_ports_link_status(ports_mask);

	pid = getpid();
	RTE_LOG(INFO, DU_UP, "========================\n");
	RTE_LOG(INFO, DU_UP, "KNI Running\n");
	RTE_LOG(INFO, DU_UP, "kill -SIGUSR1 %d\n", pid);
	RTE_LOG(INFO, DU_UP, "    Read UE Information.\n");
	RTE_LOG(INFO, DU_UP, "========================\n");
	fflush(stdout);

	ret = rte_ctrl_thread_create(&kni_link_tid,
				     "KNI link status check", NULL,
				     monitor_all_ports_link_status, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Could not create link status thread!\n");

	/* Launch per-lcore function on every lcore */
	rte_eal_mp_remote_launch(main_loop, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(i) {
		if (rte_eal_wait_lcore(i) < 0)
			return -1;
	}
	monitor_links = 0;
	pthread_join(kni_link_tid, &retval);
    
	/* Release resources */
	RTE_ETH_FOREACH_DEV(port) {
		if (!(ports_mask & (1 << port)))
			continue;
		kni_free_kni(port);
	}
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		if (kni_port_params_array[i]) {
			rte_free(kni_port_params_array[i]);
			kni_port_params_array[i] = NULL;
		}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
