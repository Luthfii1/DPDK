#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <rte_string_fns.h>

#include "cfg_file.h"

static int cfg_load_lcore(struct rte_cfgfile *cfg)
{
    int lcore_id;
    int nb_lcore_profiles;
    uint16_t port_id;
    char lcore_name[0xff];
    char *next;
    const char *entry;
    struct lcore_conf *conf;

    nb_lcore_profiles = rte_cfgfile_num_sections(cfg, "lcore", sizeof("lcore") - 1);
    printf("nb_lcore_profiles = %u\n", nb_lcore_profiles);
    for (lcore_id = 0; lcore_id < APP_MAX_LCORE; lcore_id++) {
        snprintf(lcore_name, sizeof(lcore_name), "lcore %d", lcore_id);
        
        if (!rte_cfgfile_has_section(cfg, lcore_name)) {
            continue;
        }
        if (!rte_lcore_has_role(lcore_id, ROLE_RTE)) {
            RTE_LOG(ERR, DU_UP, "lcore %d is not used in RTE, but specified in cfg file\n", lcore_id);
            return -1;
        }
        conf = &lcore_conf[lcore_id];
        
        // role
        entry = rte_cfgfile_get_entry(cfg, lcore_name, "role");
        if (!entry) {
            RTE_LOG(ERR, DU_UP, "Cfgfile: No role in lcore %d\n", lcore_id);
            return -1;
        }
        if (strcmp(entry, "dp") == 0)
            conf->role = LCORE_DP;
        else if (strcmp(entry, "kni") == 0)
            conf->role = LCORE_KNI;
        else {
            RTE_LOG(ERR, DU_UP, "Unknown role of lcore %d\n", lcore_id);
            return -1;
        }

        // port
        entry = rte_cfgfile_get_entry(cfg, lcore_name, "port");
        if (!entry) {
            RTE_LOG(ERR, DU_UP, "Cfgfile: No port in lcore %d\n", lcore_id);
            return -1;
        }
        do {
            port_id = (uint16_t) strtol(entry, &next, 10);
            if (entry == next)
                break;

            if ((conf->role == LCORE_UE || conf->role == LCORE_CU) &&
                port_role[port_id].role != 0) {
                RTE_LOG(ERR, DU_UP, "Cfgfile: port %u has role %u for lcore %u\n", port_id, port_role[port_id].role, lcore_id);
                return -1;
            }

            conf->ports[conf->nb_port++] = port_id;
            if (conf->role == LCORE_DP) {
                port_role[port_id].role = ROLE_UE;
                port_role[port_id].lcore_rx = lcore_id;
                ue_ports[nb_ue_port++] = port_id;
            }
            else if (conf->role == LCORE_KNI) {
                port_role[port_id].lcore_tx = lcore_id;
            }

            entry = next;
        } while (next);
        
        if (!conf->nb_port) {
            RTE_LOG(ERR, DU_UP, "Cfgfile: No port is specified in lcore %d\n", lcore_id);
            return -1;
        }

        conf->is_set = true;
    }

    return 0;
}

static int cfg_load_up_setting(struct rte_cfgfile *cfg)
{
    char buf[0xff];
    const char *entry;

    // if (!rte_cfgfile_has_section(cfg, "DU_UP")) {
    //     RTE_LOG(ERR, DU_UP, "Cfgfile: must specify DU_UP in cfg file\n");
    //     return -1;
    // }

    // // DU_UP DL Trunk IP
    // entry = rte_cfgfile_get_entry(cfg, "DU_UP", "dl trunk ip");
    // if (!entry) {
    //     RTE_LOG(ERR, DU_UP, "Cfgfile: No DU_UP DL Trunk IP is provided\n");
    //     return -1;
    // }
    // if (inet_pton(AF_INET, entry, &du_dl_trunk_ip) <= 0) {
    //     RTE_LOG(ERR, DU_UP, "Cfgfile: DU_UP DL Trunk IP is invalide\n");
    //     return -1;
    // }
    // RTE_LOG(INFO, DU_UP, "DU_UP DL Trunk ip is %s\n", entry);
    // // DU_UP F1-U IP
    // entry = rte_cfgfile_get_entry(cfg, "DU_UP", "f1u ip");
    // if (!entry) {
    //     RTE_LOG(ERR, DU_UP, "Cfgfile: No DU_UP F1-U IP is provided\n");
    //     return -1;
    // }
    // if (inet_pton(AF_INET, entry, &du_f1u_ip) <= 0) {
    //     RTE_LOG(ERR, DU_UP, "Cfgfile: DU_UP F1-U IP is invalide\n");
    //     return -1;
    // }
    // RTE_LOG(INFO, DU_UP, "DU_UP F1-U IP is %s\n", entry);

    return 0;
}

int load_cfg_profile(const char *profile_name)
{
    if (profile_name == NULL)
		return -1;
	struct rte_cfgfile *file = rte_cfgfile_load(profile_name, 0);

	if (file == NULL) {
        RTE_LOG(ERR, DU_UP, "Cannot load cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_OPEN;
    }

    if (cfg_load_lcore(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Failed to load lcore configuration for cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_LOAD;
    }

    if (cfg_load_up_setting(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Failed to load user plane configuration for cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_LOAD;
    }

    if (rte_cfgfile_close(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Cannot close cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_CLOSE;
    }

    return 0;
}