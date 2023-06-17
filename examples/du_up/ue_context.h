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
    ERR_UE_PROFILE_GET_DL_TRUNK_IP,
    ERR_UE_PROFILE_PARSE_DL_TRUNK_IP,
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
    uint8_t nb_qos_flow;
    struct qos_flow_params *qos_flows;
};

struct qos_flow_params {
    uint8_t qfi;
    enum qos_flow_type type;
    uint64_t gfbr;
    uint64_t mfbr;

    struct rte_meter_trtcm_params *trtcm_params;
    struct rte_meter_trtcm_profile *trtcm_profile;
    struct rte_meter_trtcm *trtcm_runtime_ctxt;
};

struct ue_info {
    uint8_t nb_drb;
    uint8_t is_gbr;
    uint8_t is_active;
    uint32_t alloc_flow_rate; // unit = Mbps
    uint16_t rnti;
    uint32_t dl_trunk_ip;
    uint8_t drb_id_array[MAX_NUM_DRB_PER_UE];
};

struct ue_info* get_ue_info_by_ue_id(uint16_t ue_id);
struct drb_params* get_drb_by_id(uint8_t drb_id);
struct drb_params* get_drb_by_dl_teid(uint32_t teid);
int load_ue_info();
void print_ue_info();

#endif /* DU_UP_UE_CONTEXT_H_ */