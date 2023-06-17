#ifndef DU_UP_UE_CONTEXT_H_
#define DU_UP_UE_CONTEXT_H_

#include <rte_meter.h>

#define MAX_NUM_UE 32
#define MAX_NUM_DRB 32
#define MAX_NUM_DRB_PER_UE 8
#define MAX_QOS_FLOW_PER_SESSION 64

enum ue_info_err_type {
    ERR_UE_PROFILE_NULL_NAME = 1,
    ERR_UE_PROFILE_OPEN,
    ERR_UE_PROFILE_CLOSE,
    ERR_UE_PROFILE_LOAD,
    ERR_UE_PROFILE_ALLOC_MEM,
    ERR_UE_PROFILE_GET_RNTI,
    ERR_UE_PROFILE_PARSE_RNTI,
    ERR_UE_PROFILE_GET_UE_TRUNK_IP,
    ERR_UE_PROFILE_PARSE_UE_TRUNK_IP,
    ERR_UE_PROFILE_GET_DU_TRUNK_IP,
    ERR_UE_PROFILE_PARSE_DU_TRUNK_IP,
    ERR_UE_PROFILE_GET_DL_TRUNK_PORT,
    ERR_UE_PROFILE_PARSE_DL_TRUNK_PORT,
    ERR_UE_PROFILE_GET_DRB_LIST,
    ERR_UE_PROFILE_PARSE_DRB_LIST,
    ERR_DRB_PROFILE_ALLOC_MEM,
    ERR_DRB_PROFILE_GET_PDCP_UL_SN,
    ERR_DRB_PROFILE_GET_PDCP_DL_SN,
    ERR_DRB_PROFILE_GET_F1U_UL_TEID,
    ERR_DRB_PROFILE_GET_F1U_DL_TEID,
    ERR_DRB_PROFILE_PARSE_F1U_UL_TEID,
    ERR_DRB_PROFILE_PARSE_F1U_DL_TEID,
    ERR_DRB_PROFILE_GET_F1U_UL_IP,
    ERR_DRB_PROFILE_PARSE_F1U_UL_IP,
    ERR_DRB_PROFILE_GET_F1U_DL_IP,
    ERR_DRB_PROFILE_PARSE_F1U_DL_IP,

    ERR_DRB_PROFILE_GET_QOS_FLOW_LIST_LEN,
    ERR_DRB_PROFILE_ALLOC_QOS_FLOW_LIST,
    ERR_DRB_PROFILE_GET_QOS_FLOW_LIST,
    ERR_DRB_PROFILE_PARSE_QOS_FLOW_LIST,

    ERR_QOS_PROFILE_GET_TYPE,
    ERR_QOS_PROFILE_UNKNOWN_TYPE,
    ERR_QOS_PROFILE_GET_GFBR,
    ERR_QOS_PROFILE_PARSE_GFBR,
    ERR_QOS_PROFILE_GET_MFBR,
    ERR_QOS_PROFILE_PARSE_MFBR,
    ERR_QOS_PROFILE_CONFIG_TRTCM,

};

enum qos_flow_type {
    QOS_FLOW_TYPE_NON_GBR = 0,
    QOS_FLOW_TYPE_GBR,
};

enum pdcp_hdr_type {
    PDCP_12_BIT = 0,
    PDCP_18_BIT
};

struct drb_params {
    uint8_t drb_id;
    uint16_t ue_id;
    struct ue_info *ue;
    enum pdcp_hdr_type ul_pdcp_hdr_type; /* 12-bit or 18-bit */
    enum pdcp_hdr_type dl_pdcp_hdr_type; /* 12-bit or 18-bit */
    uint32_t f1u_ul_teid;
    uint32_t f1u_dl_teid;
    uint32_t f1u_ul_ip; /* F1-U UP UL TNL Address in network byte order */
    uint32_t f1u_dl_ip; /* F1-U UP DL (DU-UP) TNL Address in network byte order */
    uint8_t nb_qos_flow;
    struct qos_flow_params *qos_flows;
};

struct qos_flow_statistics {
    uint64_t iteration; /* Number of loop during active state */

    uint64_t rx_pkt; /* Number of rx packets */
    uint64_t tx_pkt; /* Number of tx packets */

    uint64_t rx_bytes; /* Number of rx bytes */
    uint64_t tx_bytes; /* Number of tx bytes */
};

struct qos_flow_params {
    enum qos_flow_type type; /* GBR or Non-GBR */
    uint8_t is_active; /* Whether the qos flow continues existing */
    uint8_t qfi;
    uint16_t ue_rnti;
    uint32_t alloc_packet_quota; /* Quota of active qos flow transmitted */
	uint32_t alloc_packet_rest;  /* Rest amount of allowed transmitted packets */
    uint32_t alloc_flow_rate; /* Allocated maximum flow rate for GBR flow (Mbps) */
    uint64_t gfbr;
    uint64_t mfbr;

    uint64_t last_active_tsc; /* Last active time in tsc */
    
    struct rte_ring *rx_ring;
    struct qos_flow_statistics statistics;

    struct rte_meter_trtcm_params *trtcm_params;
    struct rte_meter_trtcm_profile *trtcm_profile;
    struct rte_meter_trtcm *trtcm_runtime_ctxt;
};

struct ue_info {
    uint8_t nb_drb;
    uint8_t nb_qos_flow;
    uint16_t rnti;
    uint32_t ue_trunk_ip;
    uint32_t du_trunk_ip;
    uint8_t port;
    uint8_t drb_id_array[MAX_NUM_DRB_PER_UE];
    struct qos_flow_params *qos_flow_array[MAX_QOS_FLOW_PER_SESSION];
};

struct ue_info* get_ue_info_by_ue_id(uint16_t ue_id);
struct drb_params* get_drb_by_id(uint8_t drb_id);
struct drb_params* get_drb_by_dl_teid(uint32_t teid);
int load_ue_info();
void print_ue_info();

extern uint32_t nb_ue;
extern struct drb_params *drb_array[MAX_NUM_DRB];
extern struct ue_info *ue_info_array[MAX_NUM_UE];

#endif /* DU_UP_UE_CONTEXT_H_ */