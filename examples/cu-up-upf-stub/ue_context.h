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
    ERR_UE_PROFILE_GET_PDU_SESSION_IP,
    ERR_UE_PROFILE_PARSE_PDU_SESSION_IP,
    ERR_UE_PROFILE_GET_DRB,
    ERR_UE_PROFILE_PARSE_DRB,
    ERR_UE_PROFILE_INSERT_DRB_TO_HASHTABLE,

    ERR_DRB_PROFILE_ALLOC_MEM,
    ERR_DRB_PROFILE_GET_PDCP_UL_SN,
    ERR_DRB_PROFILE_GET_PDCP_DL_SN,
    ERR_DRB_PROFILE_GET_F1U_UL_TEID,
    ERR_DRB_PROFILE_GET_F1U_DL_TEID,
    ERR_DRB_PROFILE_PARSE_F1U_UL_TEID,
    ERR_DRB_PROFILE_PARSE_F1U_DL_TEID,
    ERR_DRB_PROFILE_GET_F1U_DL_IP,
    ERR_DRB_PROFILE_PARSE_F1U_DL_IP,

    ERR_DRB_PROFILE_GET_DEFAULT_QFI,
    ERR_DRB_PROFILE_PARSE_DEFAULT_QFI,

};

enum qos_flow_type {
    QOS_FLOW_TYPE_NON_GBR = 0,
    QOS_FLOW_TYPE_GBR,
};

enum pdcp_hdr_type {
    PDCP_12_BIT = 0,
    PDCP_18_BIT
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

struct drb_params {
    uint8_t drb_id;
    uint16_t ue_id;
    struct ue_info *ue;
    enum pdcp_hdr_type ul_pdcp_hdr_type; /* 12-bit or 18-bit */
    enum pdcp_hdr_type dl_pdcp_hdr_type; /* 12-bit or 18-bit */
    uint32_t dl_pdcp_sn;
    uint32_t f1u_ul_teid;
    uint32_t f1u_dl_teid;
    uint32_t f1u_dl_ip; /* F1-U UP DL TNL Address in network byte order */
    
    uint8_t is_active;
    uint8_t default_qfi;
    struct qos_flow_statistics statistics;
    // uint8_t nb_qos_flow;
    // struct qos_flow_params *qos_flows;
    // struct qos_flow_params *qos_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
};

struct ue_info {
    uint16_t rnti;
    uint8_t nb_drb;
    uint32_t dl_trunk_ip;
    uint32_t pdu_sess_ip;

    struct drb_params default_drb;

    // uint8_t drb_id_array[MAX_NUM_DRB_PER_UE];
    // struct drb_params *drb_array;
    // struct drb_params *drb_array_ptr[MAX_NUM_DRB_PER_UE];
    
    // uint8_t nb_qos_flow;
    // uint8_t nb_gbr_flow;
    // uint8_t nb_ngbr_flow;
    // struct qos_flow_params *gbr_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
    // struct qos_flow_params *ngbr_flow_ptr[MAX_QOS_FLOW_PER_SESSION];
    // struct qos_flow_params *qos_flow_array[MAX_QOS_FLOW_PER_SESSION];
};

struct ue_table_entry {
    struct ue_info *ue;
    struct ue_table_entry *next;
};

struct drb_params* get_drb_by_pdu_ip(uint32_t ue_pdu_ip);
struct drb_params* get_drb_by_ul_teid(uint32_t teid);
int load_ue_info();
void print_ue_info();

#ifdef QOS_FLOW_PRESSURE_TEST
int insert_test_set();
#endif /* QOS_FLOW_PRESSURE_TEST */

extern uint32_t nb_ue;
extern struct ue_info *ue_info_array[MAX_NUM_UE];
extern struct ue_info *runtime_ue_array[MAX_NUM_UE];

#endif /* DU_UP_UE_CONTEXT_H_ */