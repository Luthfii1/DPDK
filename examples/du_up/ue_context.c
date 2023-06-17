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

static struct drb_params *drb_array[MAX_NUM_DRB];
static struct ue_info *ue_info_array[MAX_NUM_UE];
static uint32_t nb_ue = 0;

static int parse_ue_info(const char *fn);
static int configure_trTCM_profile(struct qos_flow_params *qos_flow);

struct ue_info* get_ue_info_by_ue_id(uint16_t ue_id)
{
    if (ue_id >= MAX_NUM_UE)
        return NULL;
    return ue_info_array[ue_id];
}

struct drb_params* get_drb_by_id(uint8_t drb_id)
{
    if (drb_array[drb_id])
        return drb_array[drb_id];

    return NULL;
}

struct drb_params* get_drb_by_dl_teid(uint32_t dl_teid)
{
    int i;
    for (i = 0; i < MAX_NUM_DRB; i++) {
        if (!drb_array[i])
            continue;
        // RTE_LOG(INFO, DU_UP, "Search in DRB %u (DL TEID %X, %X)\n", i, drb_array[i]->f1u_dl_teid, dl_teid);
        if (drb_array[i]->f1u_dl_teid == dl_teid)
            return drb_array[i];
    }

    return NULL;
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
    struct rte_cfgfile *file;
    struct ue_info *ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    const char *entry;
    char *next;
    char sec_name[16];
    char ring_name[MAX_RING_NAME_LEN];

    if (!ue_profile)
        return -ERR_UE_PROFILE_NULL_NAME;

    RTE_LOG(INFO, DU_UP, "Opening %s\n", ue_profile);
    file = rte_cfgfile_load(ue_profile, 0);

	if (file == NULL) {
        return -ERR_UE_PROFILE_OPEN;
    }

    ue = rte_zmalloc("UE_INFO", sizeof(*ue), RTE_CACHE_LINE_SIZE);
    ue->is_active = false;
    ue->is_gbr = false;
    
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

    // Fetch DRBs
    for (i = 0; i < ue->nb_drb; i++) {
        drb = rte_zmalloc("DRB", sizeof(struct drb_params), RTE_CACHE_LINE_SIZE);
        if (!drb) {
            ret = -ERR_DRB_PROFILE_ALLOC_MEM;
            goto drb_info_err;
        }
        drb->ue_id = nb_ue;
        drb->ue = ue;
        drb->drb_id = ue->drb_id_array[i];
        drb_array[drb->drb_id] = drb;

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
            snprintf(sec_name, sizeof(sec_name), "QoS Flow %u", qos_flow->qfi);
            // Type
            entry = rte_cfgfile_get_entry(file, sec_name, "type");
            if (!entry) {
                ret = -ERR_QOS_PROFILE_GET_TYPE;
                goto drb_info_err;
            }
            if (!strcmp(entry, "GBR")) {
                qos_flow->type = QOS_FLOW_TYPE_GBR;
            }
            else if (!strcmp(entry, "NONGBR")) {
                qos_flow->type = QOS_FLOW_TYPE_NON_GBR;
                continue;
            }
            else {
                ret = -ERR_QOS_PROFILE_UNKNOWN_TYPE;
                goto drb_info_err;
            }
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

            ue->is_gbr = true;
            ue->alloc_flow_rate += (uint16_t) ((qos_flow->gfbr + qos_flow->mfbr) / 2000000);
        }
    }

    if (rte_cfgfile_close(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Cannot close cfg file %s\n", ue_profile);
        return -ERR_UE_PROFILE_CLOSE;
    }

    ue_info_array[nb_ue++] = ue;

    return 0;

drb_info_err:
    for (i = 0; i < ue->nb_drb; i++) {
        struct drb_params **params;

        params = &drb_array[ue->drb_id_array[i]];

        if (*params == NULL)
            continue;
        if ((*params)->qos_flows) {
            for (j = 0; j < (*params)->nb_qos_flow; j++) {
                qos_flow = &((*params)->qos_flows[j]);
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
            rte_free((*params)->qos_flows);
        }
        rte_free(*params);
        *params = NULL;
    }

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

    for (i = 0; i < MAX_NUM_UE; i++) {
        ue = ue_info_array[i];
        if (!ue)
            continue;

        RTE_LOG(INFO, DU_UP, "[UE 0x%X]\n", ue->rnti);

        inet_ntop(AF_INET, &ue->dl_trunk_ip, buf, INET_ADDRSTRLEN);
        RTE_LOG(INFO, DU_UP, "  - DL Trunk IP = %s\n", buf);
        RTE_LOG(INFO, DU_UP, "  - DRB List\n");
        for (j = 0; j < ue->nb_drb; j++) {
            drb = drb_array[ue->drb_id_array[j]];
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
configure_trTCM_profile(struct qos_flow_params *qos_flow)
{
    int ret;

    qos_flow->trtcm_profile = rte_zmalloc("TRTCM_PROFILE",
        sizeof(*qos_flow->trtcm_profile), RTE_CACHE_LINE_SIZE);
    qos_flow->trtcm_params = rte_zmalloc("TRTCM_PARAMS",
        sizeof(*qos_flow->trtcm_params), RTE_CACHE_LINE_SIZE);
    qos_flow->trtcm_runtime_ctxt = rte_zmalloc("TRTCM_RT_CTXT",
        sizeof(*qos_flow->trtcm_runtime_ctxt), RTE_CACHE_LINE_SIZE);
    
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

    return 0;
}