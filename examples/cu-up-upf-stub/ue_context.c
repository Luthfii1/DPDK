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

// For fast access
// Use last 16-bit of RFSim IP to do index
struct ue_info *ue_info_array[MAX_NUM_UE];

// For timer loop iteration
struct ue_info *runtime_ue_array[MAX_NUM_UE];
uint32_t nb_ue = 0;

static int parse_ue_info(const char *fn);

struct drb_params* get_drb_by_pdu_ip(uint32_t ue_pdu_ip)
{
    uint32_t ue_table_idx = network_ip_hash(ue_pdu_ip) & UE_TABLE_MASK;
    struct ue_info* ue = ue_info_array[ue_table_idx];

    if (!ue)
        return NULL;

    return &ue->default_drb;
}

struct drb_params* get_drb_by_ul_teid(uint32_t ul_teid)
{
    struct drb_table_entry *drb_entry = drb_table_get_entry_by_ul_teid(ul_teid);
    
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

    // PDU Session IP
    entry = rte_cfgfile_get_entry(file, "UE Info", "pdu session ip");
    if (!entry) {
        ret = -ERR_UE_PROFILE_GET_PDU_SESSION_IP;
        goto ue_info_err;
    }
    if (!inet_pton(AF_INET, entry, &ue->pdu_sess_ip)) {
        ret = -ERR_UE_PROFILE_PARSE_PDU_SESSION_IP;
        goto ue_info_err;
    }
    ue_table_idx = network_ip_hash(ue->pdu_sess_ip) & UE_TABLE_MASK;

    // Default DRB Context
    drb = &ue->default_drb;
    drb->ue_id = nb_ue;
    drb->ue = ue;
    snprintf(sec_name, sizeof(sec_name), "DRB");

    // DRB ID
    entry = rte_cfgfile_get_entry(file, sec_name, "id");
    if (!entry) {
        ret = -ERR_UE_PROFILE_GET_DRB;
        goto ue_info_err;
    }
    if (parse_str_to_hex_8(entry, &drb->drb_id) < 0) {
        ret = -ERR_UE_PROFILE_PARSE_DRB;
        goto ue_info_err;
    }

    // PDCP UL SN len
    entry = rte_cfgfile_get_entry(file, sec_name, "pdcp ul sn len");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_PDCP_UL_SN;
        goto ue_info_err;
    }
    drb->ul_pdcp_hdr_type = atoi(entry) == 12 ? PDCP_12_BIT : PDCP_18_BIT;

    // PDCP DL SN len
    entry = rte_cfgfile_get_entry(file, sec_name, "pdcp dl sn len");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_PDCP_DL_SN;
        goto ue_info_err;
    }
    drb->dl_pdcp_hdr_type = atoi(entry) == 12 ? PDCP_12_BIT : PDCP_18_BIT;

    // F1-U UL TEID
    entry = rte_cfgfile_get_entry(file, sec_name, "f1u ul teid");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_F1U_UL_TEID;
        goto ue_info_err;
    }
    if (parse_str_to_hex_32(entry, &drb->f1u_ul_teid) < 0) {
        ret = -ERR_DRB_PROFILE_PARSE_F1U_UL_TEID;
        goto ue_info_err;
    }

    // F1-U DL TEID
    entry = rte_cfgfile_get_entry(file, sec_name, "f1u dl teid");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_F1U_DL_TEID;
        goto ue_info_err;
    }
    if (parse_str_to_hex_32(entry, &drb->f1u_dl_teid) < 0) {
        ret = -ERR_DRB_PROFILE_PARSE_F1U_DL_TEID;
        goto ue_info_err;
    }

    // F1-U DL UP TNL Address
    entry = rte_cfgfile_get_entry(file, sec_name, "f1u dl ip");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_F1U_DL_IP;
        goto ue_info_err;
    }
    if (!inet_pton(AF_INET, entry, &drb->f1u_dl_ip)) {
        ret = -ERR_DRB_PROFILE_PARSE_F1U_DL_IP;
        goto ue_info_err;
    }

    // Default QoS Flow ID (QFI)
    entry = rte_cfgfile_get_entry(file, sec_name, "default qfi");
    if (!entry) {
        ret = -ERR_DRB_PROFILE_GET_DEFAULT_QFI;
        goto ue_info_err;
    }
    if (parse_str_to_hex_8(entry, &drb->default_qfi) < 0) {
        ret = -ERR_DRB_PROFILE_PARSE_DEFAULT_QFI;
        goto ue_info_err;
    }

    if (drb_table_insert(drb) < 0) {
        ret = -ERR_UE_PROFILE_INSERT_DRB_TO_HASHTABLE;
        goto ue_info_err;
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
        drb = &ue->default_drb;

        inet_ntop(AF_INET, &drb->f1u_dl_ip, buf, INET_ADDRSTRLEN);

        RTE_LOG(INFO, DU_UP, "[UE 0x%X]\n", ue->rnti);
        RTE_LOG(INFO, DU_UP, "  - Default DRB %u\n", drb->drb_id);
        RTE_LOG(INFO, DU_UP, "    - PDCP UL SN length = %u\n", drb->ul_pdcp_hdr_type ? 18 : 12);
        RTE_LOG(INFO, DU_UP, "    - PDCP DL SN length = %u\n", drb->dl_pdcp_hdr_type ? 18 : 12);
        RTE_LOG(INFO, DU_UP, "    - F1-U UL TEID = 0x%08X\n", drb->f1u_ul_teid);
        RTE_LOG(INFO, DU_UP, "    - F1-U DL TEID = 0x%08X\n", drb->f1u_dl_teid);
        RTE_LOG(INFO, DU_UP, "    - F1-U UP DL TNL Address = %s\n", buf);
        RTE_LOG(INFO, DU_UP, "    - Default QoS Flow %u\n", drb->default_qfi);
    }

    RTE_LOG(INFO, DU_UP, "==============================\n");
}

#ifdef QOS_FLOW_PRESSURE_TEST

static struct ue_info* create_dummy_ue(uint32_t rnti, rte_be32_t pdu_ip)
{
    int i, j;
    char *f1u_dl_ip_str = "172.20.0.5";
    rte_be32_t f1u_dl_ip;
    struct ue_info *new_ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    static uint32_t base_teid = 0x1;

    new_ue = rte_zmalloc("UE_INFO", sizeof(struct ue_info), RTE_CACHE_LINE_SIZE);

    if (!new_ue) {
        goto mem_err;
    }

    inet_pton(AF_INET, f1u_dl_ip_str, &f1u_dl_ip);

    new_ue->rnti = rnti;
    new_ue->pdu_sess_ip = pdu_ip;
    new_ue->nb_drb = 1;

    new_ue->default_drb.drb_id = 1;
    new_ue->default_drb.ul_pdcp_hdr_type = new_ue->default_drb.dl_pdcp_hdr_type = PDCP_18_BIT;
    new_ue->default_drb.f1u_dl_ip = f1u_dl_ip;
    new_ue->default_drb.f1u_ul_teid = base_teid;
    new_ue->default_drb.f1u_dl_teid = base_teid;
    new_ue->default_drb.default_qfi = 9;

    if (drb_table_insert(&new_ue->default_drb) < 0) {
        goto mem_err;
    }

    // RTE_LOG(INFO, DU_UP, "insert DRB with F1-U UL/DL TEID %08X/%08X\n", new_ue->default_drb.f1u_ul_teid, new_ue->default_drb.f1u_dl_teid);

    base_teid += new_ue->nb_drb;

    return new_ue;

mem_err:
    return NULL;
}

int insert_test_set()
{
    int i, j, k;
    char pdu_ip_str[INET_ADDRSTRLEN];
    uint32_t pdu_ip;

    uint32_t rnti = 0x1;
    uint8_t nb_ue_group = 200;
    uint8_t target_nb_ue = 250;

    struct ue_info *ue;
    struct drb_params *drb;
    struct qos_flow_params *qos_flow;
    struct rte_ether_addr ue_rfsim_mac;
    uint16_t ue_port = 0;
    uint32_t ue_table_idx;

    for (i = 1; i <= nb_ue_group; i++) {
        for (j = 1; j <= target_nb_ue; j++) {
            snprintf(pdu_ip_str, sizeof(pdu_ip_str), "10.60.%u.%u", i, j);
            inet_pton(AF_INET, pdu_ip_str, &pdu_ip);

            ue = create_dummy_ue(rnti++, pdu_ip);

            if (!ue) {
                RTE_LOG(ERR, DU_UP, "No enough memory for allocation of dummy ue\n");
                goto err;
            }
            runtime_ue_array[nb_ue++] = ue;
            ue_table_idx = network_ip_hash(pdu_ip) & UE_TABLE_MASK;
            // RTE_LOG(INFO, DU_UP, "insert UE in table idx %u (mask = %u)\n", network_ip_hash(pdu_ip), UE_TABLE_MASK);
            ue_info_array[ue_table_idx] = ue;
        }
    }

    return 0;

err:
    for (i = 0; i < nb_ue; i++) {
        ue = runtime_ue_array[i];
        rte_free(ue);
    }
    return -1;
}

#endif /* QOS_FLOW_PRESSURE_TEST */