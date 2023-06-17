#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_log.h>
#include <rte_cfgfile.h>

#include "common.h"
#include "ue_context.h"
#include "drb_table.h"
#include "arp_table.h"

// For fast access
// Use last 16-bit of RFSim IP to do index
struct ue_info *ue_info_array[MAX_NUM_UE];

// For timer loop iteration
struct ue_info *runtime_ue_array[MAX_NUM_UE];
uint32_t nb_ue = 0;

static int parse_ue_info(const char *fn);
static int init_trTCM_objects(struct qos_flow_params *qos_flow);
static int configure_trTCM_profile(struct qos_flow_params *qos_flow);

struct drb_params* get_drb_by_rfsim(rte_be32_t ue_rfsim_ip, uint8_t drb_id)
{
    uint32_t ue_table_idx = network_ip_hash(ue_rfsim_ip) & UE_TABLE_MASK;
    struct ue_info* ue = ue_info_array[ue_table_idx];

    rte_prefetch0((void*) ue);

    if (!ue)
        return NULL;

    return ue->drb_array_ptr[drb_id];
}

struct drb_params* get_drb_by_dl_teid(uint32_t dl_teid)
{
    struct drb_table_entry *drb_entry = drb_table_get_entry_by_dl_teid(dl_teid);
    
    if (!drb_entry)
        return NULL;
    
    return drb_entry->drb_context;
}

int load_ue_info()
{
    int ret;
    char ue_info_fn[300];
    struct dirent *ue_dirent;
	DIR *ue_dir;
    FILE *ue_info_file;
    uint64_t start_tsc = rte_rdtsc(), end_tsc;

	ue_dir = opendir("/tmp/ue_info/");

    if (!ue_dir) {
        printf("No /tmp/ue_info\n");
        return -1;
    }

    while((ue_dirent = readdir(ue_dir)) != NULL)
	{
        if (strncmp(ue_dirent->d_name, "UE_", 3))
            continue;
        
        snprintf(ue_info_fn, sizeof(ue_info_fn), "/tmp/ue_info/%s", ue_dirent->d_name);
        ret = parse_ue_info(ue_info_fn);
        if (ret < 0) {
            RTE_LOG(WARNING, DU_UP, "Failed to load %s information (err %d)\n", ue_info_fn, ret);
            continue;
        }
        remove(ue_info_fn);
    }

    end_tsc = rte_rdtsc();
    RTE_LOG(DEBUG, DU_UP, "Cost of loading UE information = %lu cycles\n", end_tsc - start_tsc);

    return 0;
}

static int parse_ue_info(const char *ue_profile)
{
    uint8_t drb_id, qfi;
    int i, j;
    int ret, num;
    uint32_t ue_table_idx;
    struct rte_cfgfile *file;
    struct ue_info *ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    struct rte_ring *ring;
    const char *entry;
    char *next;
    char sec_name[16];

    if (!ue_profile)
        return -ERR_UE_PROFILE_NULL_NAME;

    RTE_LOG(INFO, DU_UP, "Opening %s\n", ue_profile);
    file = rte_cfgfile_load(ue_profile, 0);

	if (file == NULL) {
        return -ERR_UE_PROFILE_OPEN;
    }

    ue = rte_zmalloc("UE_INFO", sizeof(*ue), RTE_CACHE_LINE_SIZE);
    
    if (!ue)
        return -ERR_UE_PROFILE_ALLOC_MEM;

    // RNTI
    entry = rte_cfgfile_get_entry(file, "UE Info", "rnti");
    if (!entry) {
        ret = -ERR_UE_PROFILE_GET_RNTI;
        goto ue_info_err;
    }
    if (parse_str_to_hex_16(entry, &ue->rnti) < 0) {
        ret = -ERR_UE_PROFILE_PARSE_RNTI;
        goto ue_info_err;
    }

    // DL Trunk
    entry = rte_cfgfile_get_entry(file, "UE Info", "dl trunk ip");
    if (!entry) {
        ret = -ERR_UE_PROFILE_GET_DL_TRUNK_IP;
        goto ue_info_err;
    }
    if (!inet_pton(AF_INET, entry, &ue->dl_trunk_ip)) {
        ret = -ERR_UE_PROFILE_PARSE_DL_TRUNK_IP;
        goto ue_info_err;
    }
    ue_table_idx = network_ip_hash(ue->dl_trunk_ip) & UE_TABLE_MASK;

    // DRB List
    entry = rte_cfgfile_get_entry(file, "UE Info", "drb");
    if (!entry) {
        ret = -ERR_UE_PROFILE_GET_DRB_LIST;
        goto ue_info_err;
    }
    do {
        drb_id = strtoul(entry, &next, 10);
        
        if (next == entry)
            break;
        
        ue->drb_id_array[ue->nb_drb++] = drb_id;
        entry = next;
    } while (1);
    if (ue->nb_drb == 0) {
        ret = -ERR_UE_PROFILE_PARSE_DRB_LIST;
        goto ue_info_err;
    }
    ue->drb_array = rte_zmalloc("DRB_LIST", sizeof(struct drb_params) * ue->nb_drb, RTE_CACHE_LINE_SIZE);
    if (!ue->drb_array) {
        ret = -ERR_DRB_PROFILE_ALLOC_MEM;
        goto drb_info_err;
    }

    // Fetch DRBs
    for (i = 0; i < ue->nb_drb; i++) {
        drb = &ue->drb_array[i];

        drb->ue_id = nb_ue;
        drb->ue = ue;
        drb->drb_id = ue->drb_id_array[i];
        ue->drb_array_ptr[drb->drb_id] = drb;
        // drb_array[drb->drb_id] = drb;

        snprintf(sec_name, sizeof(sec_name), "DRB %u", drb->drb_id);
        // PDCP UL SN len
        entry = rte_cfgfile_get_entry(file, sec_name, "pdcp ul sn len");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_PDCP_UL_SN;
            goto drb_info_err;
        }
        drb->ul_pdcp_hdr_type = atoi(entry) == 12 ? PDCP_12_BIT : PDCP_18_BIT;
        // PDCP DL SN len
        entry = rte_cfgfile_get_entry(file, sec_name, "pdcp dl sn len");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_PDCP_DL_SN;
            goto drb_info_err;
        }
        drb->dl_pdcp_hdr_type = atoi(entry) == 12 ? PDCP_12_BIT : PDCP_18_BIT;
        // F1-U UL TEID
        entry = rte_cfgfile_get_entry(file, sec_name, "f1u ul teid");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_F1U_UL_TEID;
            goto drb_info_err;
        }
        if (parse_str_to_hex_32(entry, &drb->f1u_ul_teid) < 0) {
            ret = -ERR_DRB_PROFILE_PARSE_F1U_UL_TEID;
            goto drb_info_err;
        }
        // F1-U DL TEID
        entry = rte_cfgfile_get_entry(file, sec_name, "f1u dl teid");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_F1U_DL_TEID;
            goto drb_info_err;
        }
        if (parse_str_to_hex_32(entry, &drb->f1u_dl_teid) < 0) {
            ret = -ERR_DRB_PROFILE_PARSE_F1U_DL_TEID;
            goto drb_info_err;
        }
        // F1-U UL UP TNL Address
        entry = rte_cfgfile_get_entry(file, sec_name, "f1u ul ip");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_F1U_UL_IP;
            goto drb_info_err;
        }
        if (!inet_pton(AF_INET, entry, &drb->f1u_ul_ip)) {
            ret = -ERR_DRB_PROFILE_PARSE_F1U_UL_IP;
            goto drb_info_err;
        }

        if (drb_table_insert(drb) < 0) {
            ret = -ERR_UE_PROFILE_INSERT_DRB_TO_HASHTABLE;
            goto drb_info_err;
        }

        // QoS Flow List
        entry = rte_cfgfile_get_entry(file, sec_name, "number of qos flow");
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_QOS_FLOW_LIST_LEN;
            goto ue_info_err;
        }
        drb->nb_qos_flow = (uint8_t) atoi(entry);
        drb->qos_flows = rte_zmalloc("QOS_FLOW_LIST",
            sizeof(struct qos_flow_params) * drb->nb_qos_flow, RTE_CACHE_LINE_SIZE);
        if (!drb->qos_flows) {
            ret = -ERR_DRB_PROFILE_ALLOC_QOS_FLOW_LIST;
            goto drb_info_err;
        }
        entry = rte_cfgfile_get_entry(file, sec_name, "qos flow");
        j = 0;
        if (!entry) {
            ret = -ERR_DRB_PROFILE_GET_QOS_FLOW_LIST;
            goto ue_info_err;
        }
        do {
            qfi = strtoul(entry, &next, 10);
            
            if (next == entry)
                break;
            
            drb->qos_flows[j++].qfi = qfi;
            entry = next;
        } while (1);
        if (j != drb->nb_qos_flow) {
            ret = -ERR_DRB_PROFILE_PARSE_QOS_FLOW_LIST;
            goto drb_info_err;
        }

        // Fetch QoS Flows
        for (j = 0; j < drb->nb_qos_flow; j++) {
            qos_flow = &drb->qos_flows[j];
            drb->qos_flow_ptr[qos_flow->qfi] = qos_flow;
            // Store pointer of qos flow to UE context
            ue->qos_flow_array[ue->nb_qos_flow++] = qos_flow;
            qos_flow->ue_rnti = ue->rnti;
            snprintf(sec_name, sizeof(sec_name), "QoS Flow %u", qos_flow->qfi);
            // Type
            entry = rte_cfgfile_get_entry(file, sec_name, "type");
            if (!entry) {
                ret = -ERR_QOS_PROFILE_GET_TYPE;
                goto drb_info_err;
            }
            if (!strcmp(entry, "GBR")) {
                qos_flow->type = QOS_FLOW_TYPE_GBR;
                ue->gbr_flow_ptr[ue->nb_gbr_flow++] = qos_flow;

                // GFBR
                entry = rte_cfgfile_get_entry(file, sec_name, "gfbr");
                if (!entry) {
                    ret = -ERR_QOS_PROFILE_GET_GFBR;
                    goto drb_info_err;
                }
                if (parse_str_to_decimal_64(entry, &qos_flow->gfbr) < 0) {
                    ret = -ERR_QOS_PROFILE_PARSE_GFBR;
                    goto drb_info_err;
                }
                // MFBR
                entry = rte_cfgfile_get_entry(file, sec_name, "mfbr");
                if (!entry) {
                    ret = -ERR_QOS_PROFILE_GET_MFBR;
                    goto drb_info_err;
                }
                if (parse_str_to_decimal_64(entry, &qos_flow->mfbr) < 0) {
                    ret = -ERR_QOS_PROFILE_PARSE_MFBR;
                    goto drb_info_err;
                }

                // Only GBR flow access to these code
                if (configure_trTCM_profile(qos_flow) < 0) {
                    ret = -ERR_QOS_PROFILE_CONFIG_TRTCM;
                    goto drb_info_err;
                }
            }
            else if (!strcmp(entry, "NONGBR")) {
                qos_flow->type = QOS_FLOW_TYPE_NON_GBR;
                ue->ngbr_flow_ptr[ue->nb_ngbr_flow++] = qos_flow;

                if (init_trTCM_objects(qos_flow) < 0) {
                    ret = -ERR_QOS_PROFILE_CONFIG_TRTCM;
                    goto drb_info_err;
                }
            }
            else {
                ret = -ERR_QOS_PROFILE_UNKNOWN_TYPE;
                goto drb_info_err;
            }
        }
    }

    if (rte_cfgfile_close(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Cannot close cfg file %s\n", ue_profile);
        return -ERR_UE_PROFILE_CLOSE;
    }

    ue_info_array[ue_table_idx] = ue;
    runtime_ue_array[nb_ue] = ue;
    nb_ue++;
    RTE_LOG(INFO, DU_UP, "Complete parsing UE info for UE %4X\n", ue->rnti);

    return 0;

drb_info_err:
    for (i = 0; i < ue->nb_drb; i++) {
        struct drb_params *drb;

        drb = &ue->drb_array[i];
        if (drb->qos_flows) {
            for (j = 0; j < drb->nb_qos_flow; j++) {
                qos_flow = &drb->qos_flows[j];
                if (qos_flow->trtcm_params) {
                    rte_free(qos_flow->trtcm_params);
                }
                if (qos_flow->trtcm_profile) {
                    rte_free(qos_flow->trtcm_profile);
                }
                if (qos_flow->trtcm_runtime_ctxt) {
                    rte_free(qos_flow->trtcm_runtime_ctxt);
                }
            }
            rte_free(drb->qos_flows);
        }
    }
    rte_free(ue->drb_array);

ue_info_err:
    printf("UE Error occurs\n");
    rte_free(ue);
    return ret;
}

void
print_ue_info()
{
    int i, j, k;
    struct ue_info *ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    char buf[INET_ADDRSTRLEN];

    if (!nb_ue)
        return;

    RTE_LOG(INFO, DU_UP, "==============================\n");

    for (i = 0; i < nb_ue; i++) {
        ue = runtime_ue_array[i];

        RTE_LOG(INFO, DU_UP, "[UE 0x%X]\n", ue->rnti);

        inet_ntop(AF_INET, &ue->dl_trunk_ip, buf, INET_ADDRSTRLEN);
        RTE_LOG(INFO, DU_UP, "  - DL Trunk IP = %s\n", buf);
        RTE_LOG(INFO, DU_UP, "  - DRB List\n");
        for (j = 0; j < ue->nb_drb; j++) {
            drb = &ue->drb_array[j];
            RTE_LOG(INFO, DU_UP, "  [DRB %u]\n", drb->drb_id);
            RTE_LOG(INFO, DU_UP, "    - PDCP UL SN length = %u\n", drb->ul_pdcp_hdr_type ? 18 : 12);
            RTE_LOG(INFO, DU_UP, "    - PDCP DL SN length = %u\n", drb->dl_pdcp_hdr_type ? 18 : 12);
            RTE_LOG(INFO, DU_UP, "    - F1-U UL TEID = 0x%X\n", drb->f1u_ul_teid);
            RTE_LOG(INFO, DU_UP, "    - F1-U DL TEID = 0x%X\n", drb->f1u_dl_teid);

            inet_ntop(AF_INET, &drb->f1u_ul_ip, buf, INET_ADDRSTRLEN);
            RTE_LOG(INFO, DU_UP, "    - F1-U UP UL TNL Address = %s\n", buf);
            RTE_LOG(INFO, DU_UP, "    - QoS Flow List\n");
            for (k = 0; k < drb->nb_qos_flow; k++) {
                qos_flow = &drb->qos_flows[k];
                RTE_LOG(INFO, DU_UP, "    [QoS Flow %u]\n", qos_flow->qfi);
                if (qos_flow->type) {
                    RTE_LOG(INFO, DU_UP, "      - Type = GBR\n");
                    RTE_LOG(INFO, DU_UP, "      - GFBR = %lu bps\n", qos_flow->gfbr);
                    RTE_LOG(INFO, DU_UP, "      - MFBR = %lu bps\n", qos_flow->mfbr);
                }
                else {
                    RTE_LOG(INFO, DU_UP, "      - Type = Non-GBR\n");
                }
            }
        }
    }

    RTE_LOG(INFO, DU_UP, "==============================\n");
}

static int
init_trTCM_objects(struct qos_flow_params *qos_flow)
{
    int ret;

    qos_flow->trtcm_profile = rte_zmalloc("TRTCM_PROFILE",
        sizeof(*qos_flow->trtcm_profile), RTE_CACHE_LINE_SIZE);

    if (!qos_flow->trtcm_profile) {
        RTE_LOG(ERR, DU_UP, "Could not allocate trtcm_profile for QoS flow %u of UE %04X\n", qos_flow->qfi, qos_flow->ue_rnti);
        return -1;
    }

    qos_flow->trtcm_params = rte_zmalloc("TRTCM_PARAMS",
        sizeof(*qos_flow->trtcm_params), RTE_CACHE_LINE_SIZE);

    if (!qos_flow->trtcm_params) {
        RTE_LOG(ERR, DU_UP, "Could not allocate trtcm_params for QoS flow %u of UE %04X\n", qos_flow->qfi, qos_flow->ue_rnti);
        return -1;
    }

    qos_flow->trtcm_runtime_ctxt = rte_zmalloc("TRTCM_RT_CTXT",
        sizeof(*qos_flow->trtcm_runtime_ctxt), RTE_CACHE_LINE_SIZE);

    if (!qos_flow->trtcm_runtime_ctxt) {
        RTE_LOG(ERR, DU_UP, "Could not allocate trtcm_runtime_ctxt for QoS flow %u of UE %04X\n", qos_flow->qfi, qos_flow->ue_rnti);
        return -1;
    }

    qos_flow->dl_trtcm_runtime_ctxt = rte_zmalloc("TRTCM_RT_CTXT",
        sizeof(*qos_flow->dl_trtcm_runtime_ctxt), RTE_CACHE_LINE_SIZE);

    if (!qos_flow->dl_trtcm_runtime_ctxt) {
        RTE_LOG(ERR, DU_UP, "Could not allocate dl_trtcm_runtime_ctxt for QoS flow %u of UE %04X\n", qos_flow->qfi, qos_flow->ue_rnti);
        return -1;
    }

    return 0;
}

static int
configure_trTCM_profile(struct qos_flow_params *qos_flow)
{
    int ret;

    ret = init_trTCM_objects(qos_flow);

    if (ret)
        return ret;
    
    // unit = Bytes
    qos_flow->trtcm_params->cir = qos_flow->gfbr / 8;
    qos_flow->trtcm_params->pir = qos_flow->mfbr / 8;
    // 10 Gbps in 10 ms
    // unit = Bytes
    qos_flow->trtcm_params->cbs = 10000000000 / 8 / 100;
    qos_flow->trtcm_params->pbs = 10000000000 / 8 / 100;

    ret = rte_meter_trtcm_profile_config(qos_flow->trtcm_profile, qos_flow->trtcm_params);

    if (ret)
        return ret;

    ret = rte_meter_trtcm_config(qos_flow->trtcm_runtime_ctxt, qos_flow->trtcm_profile);

    if (ret)
        return ret;

    ret = rte_meter_trtcm_config(qos_flow->dl_trtcm_runtime_ctxt, qos_flow->trtcm_profile);

    if (ret)
        return ret;

    return 0;
}

#ifdef QOS_FLOW_PRESSURE_TEST

static struct qos_flow_params* create_dummy_qos_flow_list(
    struct drb_params *drb,
    uint8_t base_qfi,
    uint8_t nb_qos_flow
)
{
    int i;
    struct qos_flow_params *qos_flow_list, *qos_flow;
    struct ue_info *ue = drb->ue;

    qos_flow_list = rte_zmalloc("QOS_FLOW_LIST", sizeof(struct qos_flow_params) * nb_qos_flow, RTE_CACHE_LINE_SIZE);

    if (!qos_flow_list) {
        RTE_LOG(ERR, DU_UP, "No enough memory for allocation of dummy qos flow list for DRB %u\n", drb->drb_id);
        goto mem_err;
    }

    for (i = 0; i < nb_qos_flow; i++) {
        qos_flow = &qos_flow_list[i];

        qos_flow->qfi = base_qfi + i;
        qos_flow->ue_rnti = ue->rnti;
        qos_flow->is_active = false;
        qos_flow->type = QOS_FLOW_TYPE_NON_GBR;

        if (init_trTCM_objects(qos_flow) < 0) {
            goto qos_flow_err;
        }
        drb->qos_flow_ptr[qos_flow->qfi] = qos_flow;
        ue->qos_flow_array[ue->nb_qos_flow++] = qos_flow;

        ue->ngbr_flow_ptr[ue->nb_ngbr_flow++] = qos_flow;
    }

    return qos_flow_list;

qos_flow_err:
    rte_free(qos_flow_list);
mem_err:
    return NULL;
}

static struct drb_params* create_dummy_drb_list(
    struct ue_info *ue, uint8_t base_drb_id, uint32_t base_teid,
    rte_be32_t f1u_ul_ip, uint8_t nb_drb
)
{
    int i;
    struct drb_params *drb_list, *drb;

    drb_list = rte_zmalloc("DRB_LIST", sizeof(struct drb_params) * nb_drb, RTE_CACHE_LINE_SIZE);

    if (!drb_list) {
        RTE_LOG(ERR, DU_UP, "No enough memory for allocation of dummy drb for UE %04X\n", ue->rnti);
        goto mem_err;
    }

    for (i = 0; i < nb_drb; i++) {
        drb = &drb_list[i];
        drb->drb_id = base_drb_id + i;
        drb->f1u_ul_ip = f1u_ul_ip;
        drb->f1u_ul_teid = drb->f1u_dl_teid = base_teid + i;
        drb->ul_pdcp_hdr_type = drb->dl_pdcp_hdr_type = PDCP_18_BIT;
        drb->ue = ue;
        drb->nb_qos_flow = 1;

        drb->qos_flows = create_dummy_qos_flow_list(drb, 9, drb->nb_qos_flow);
        if (!drb->qos_flows) {
            goto drb_err;
        }
        ue->drb_array_ptr[drb->drb_id] = drb;
        drb_table_insert(drb);
    }

    return drb_list;
drb_err:
    rte_free(drb_list);
mem_err:
    return NULL;
}

static struct ue_info* create_dummy_ue(uint32_t rnti, rte_be32_t rfsim_ip)
{
    int i, j;
    char *f1u_ul_ip_str = "172.20.0.1";
    rte_be32_t f1u_ul_ip;
    struct ue_info *new_ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    static uint32_t base_teid = 0x1;

    new_ue = rte_zmalloc("UE_INFO", sizeof(struct ue_info), RTE_CACHE_LINE_SIZE);

    if (!new_ue) {
        goto mem_err;
    }

    inet_pton(AF_INET, f1u_ul_ip_str, &f1u_ul_ip);

    new_ue->rnti = rnti;
    new_ue->dl_trunk_ip = rfsim_ip;
    new_ue->nb_drb = 1;
    new_ue->drb_array = create_dummy_drb_list(new_ue, 1, base_teid, f1u_ul_ip, new_ue->nb_drb);

    if (!new_ue->drb_array) {
        goto ue_err;
    }

    base_teid += new_ue->nb_drb;

    return new_ue;

ue_err:
    rte_free(new_ue);
mem_err:
    return NULL;
}

int insert_test_set()
{
    int i, j, k;
    char rfsim_str[INET_ADDRSTRLEN];
    uint32_t rfsim_ip;

    uint32_t rnti = 0x1;
    uint8_t nb_ue_group = 200;
    uint8_t target_nb_ue = 250;

    struct ue_info *ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    struct rte_ether_addr ue_rfsim_mac;
    uint16_t ue_port = 0;
    uint32_t ue_table_idx;

    rte_ether_unformat_addr("26:44:7a:05:ba:0a", &ue_rfsim_mac);

    for (i = 1; i <= nb_ue_group; i++) {
        for (j = 1; j <= target_nb_ue; j++) {
            snprintf(rfsim_str, sizeof(rfsim_str), "172.19.%u.%u", i, j);
            inet_pton(AF_INET, rfsim_str, &rfsim_ip);

            ue = create_dummy_ue(rnti++, rfsim_ip);

            if (!ue) {
                RTE_LOG(ERR, DU_UP, "No enough memory for allocation of dummy ue\n");
                goto err;
            }
            arp_table_insert(ue_port, rfsim_ip, ue_rfsim_mac);
            runtime_ue_array[nb_ue++] = ue;
            ue_table_idx = network_ip_hash(rfsim_ip) & UE_TABLE_MASK;
            ue_info_array[ue_table_idx] = ue;
        }
    }
    

    return 0;

err:
    for (i = 0; i < nb_ue; i++) {
        ue = runtime_ue_array[i];
        for (j = 0; j < ue->nb_drb; j++) {
            drb = &ue->drb_array[j];

            if (drb->qos_flows) {
                for (k = 0; k < drb->nb_qos_flow; k++) {
                    qos_flow = &drb->qos_flows[k];
                    if (qos_flow->trtcm_params) {
                        rte_free(qos_flow->trtcm_params);
                    }
                    if (qos_flow->trtcm_profile) {
                        rte_free(qos_flow->trtcm_profile);
                    }
                    if (qos_flow->trtcm_runtime_ctxt) {
                        rte_free(qos_flow->trtcm_runtime_ctxt);
                    }
                }
                rte_free(drb->qos_flows);
            }
        }
        rte_free(ue->drb_array);
        rte_free(ue);
    }
    return -1;
}

#endif /* QOS_FLOW_PRESSURE_TEST */