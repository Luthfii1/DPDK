#ifndef DU_UP_UE_CONTEXT_H_
#define DU_UP_UE_CONTEXT_H_

#include <rte_meter.h>

#define MAX_NUM_UE 65536
#define MAX_NUM_DRB_PER_UE 32
#define MAX_QOS_FLOW_PER_SESSION 64

#define UE_TABLE_MASK (MAX_NUM_UE - 1)

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
    ERR_UE_PROFILE_INSERT_DRB_TO_HASHTABLE,
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
    struct qos_flow_params *qos_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
};

struct qos_flow_statistics {
    uint64_t iteration; /* Number of loop during active state */

    uint64_t ul_rx_pkt; /* Number of UL rx packets */
    uint64_t dl_rx_pkt; /* Number of DL rx packets */
    uint64_t ul_tx_pkt; /* Number of UL tx packets */
    uint64_t dl_tx_pkt; /* Number of DL tx packets */

    uint64_t ul_rx_bytes; /* Number of UL rx bytes */
    uint64_t dl_rx_bytes; /* Number of DL rx bytes */
    uint64_t ul_tx_bytes; /* Number of UL tx bytes */
    uint64_t dl_tx_bytes; /* Number of DL tx bytes */
};

struct qos_flow_params {
    enum qos_flow_type type; /* GBR or Non-GBR */
    uint8_t is_active; /* Whether the qos flow continues existing */
    uint8_t qfi;
    uint16_t ue_rnti;
    uint64_t gfbr;
    uint64_t mfbr;

    uint64_t last_active_tsc; /* Last active time in tsc */
    
    struct qos_flow_statistics statistics;

    struct rte_meter_trtcm_params *trtcm_params;
    struct rte_meter_trtcm_profile *trtcm_profile;

    struct rte_meter_trtcm *trtcm_runtime_ctxt;
    struct rte_meter_trtcm *dl_trtcm_runtime_ctxt;
};

struct ue_info {
    uint16_t rnti;
    uint8_t nb_drb;
    uint32_t dl_trunk_ip;
    uint8_t drb_id_array[MAX_NUM_DRB_PER_UE];
    struct drb_params *drb_array;
    struct drb_params *drb_array_ptr[MAX_NUM_DRB_PER_UE];
    
    uint8_t nb_qos_flow;
    uint8_t nb_gbr_flow;
    uint8_t nb_ngbr_flow;
    struct qos_flow_params *gbr_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
    struct qos_flow_params *ngbr_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
    struct qos_flow_params *qos_flow_array[MAX_QOS_FLOW_PER_SESSION];
};

struct ue_table_entry {
    struct ue_info *ue;
    struct ue_table_entry *next;
};

struct drb_params* get_drb_by_rfsim(uint32_t ue_rfsim_ip, uint8_t drb_id);
struct drb_params* get_drb_by_dl_teid(uint32_t teid);
int load_ue_info();
void print_ue_info();
int insert_test_set();

extern uint32_t nb_ue;
extern struct ue_info *ue_info_array[MAX_NUM_UE];
extern struct ue_info *runtime_ue_array[MAX_NUM_UE];

#endif /* DU_UP_UE_CONTEXT_H_ */