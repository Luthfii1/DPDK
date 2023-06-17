#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <rte_string_fns.h>
#include <rte_ether.h>

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
        conf->is_set = true;
        
        // role
        entry = rte_cfgfile_get_entry(cfg, lcore_name, "role");
        if (!entry) {
            RTE_LOG(ERR, DU_UP, "Cfgfile: No role in lcore %d\n", lcore_id);
            return -1;
        }
        if (strcmp(entry, "du") == 0) {
            conf->role = LCORE_DU;
        }
        else if (strcmp(entry, "dn") == 0) {
            conf->role = LCORE_DN;
        }
        else if (strcmp(entry, "stat") == 0) {
            conf->role = LCORE_STAT;
            continue;
        }
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

            // Only accept one port
            if (conf->nb_port > 0)
                break;

            conf->ports[conf->nb_port++] = port_id;
            if (conf->role == LCORE_DU) {
                du_port = port_id;
            }
            else if (conf->role == LCORE_DN) {
                dn_port = port_id;
            }

            entry = next;
        } while (next);
        
        if (!conf->nb_port) {
            RTE_LOG(ERR, DU_UP, "Cfgfile: No port is specified in lcore %d\n", lcore_id);
            return -1;
        }
    }

    return 0;
}

static int cfg_load_network_setting(struct rte_cfgfile *cfg)
{
    char buf[0xff];
    const char *entry;
    const char *network_sec = "network";

    if (!rte_cfgfile_has_section(cfg, network_sec)) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: must specify DU_UP in cfg file\n");
        return -1;
    }

    // DU_UP F1-U MAC
    entry = rte_cfgfile_get_entry(cfg, network_sec, "du f1u mac");
    if (!entry) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: No DU_UP F1-U MAC is provided\n");
        return -1;
    }
    if (rte_ether_unformat_addr(entry, &du_f1u_mac) < 0) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: DU_UP F1-U MAC is invalid\n");
        return -1;
    }
    RTE_LOG(INFO, DU_UP, "DU_UP F1-U MAC is %s\n", entry);

    // CU_UP F1-U IP
    entry = rte_cfgfile_get_entry(cfg, network_sec, "cu f1u ip");
    if (!entry) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: No CU_UP F1-U IP is provided\n");
        return -1;
    }
    if (inet_pton(AF_INET, entry, &cu_f1u_ip) <= 0) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: CU_UP F1-U IP is invalid\n");
        return -1;
    }
    RTE_LOG(INFO, DU_UP, "CU_UP F1-U IP is %s\n", entry);

    // Data Network MAC
    entry = rte_cfgfile_get_entry(cfg, network_sec, "dn mac");
    if (!entry) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: No Data Network MAC is provided\n");
        return -1;
    }
    if (rte_ether_unformat_addr(entry, &dn_mac) < 0) {
        RTE_LOG(ERR, DU_UP, "Cfgfile: Data Network MAC is invalid\n");
        return -1;
    }
    RTE_LOG(INFO, DU_UP, "Data Network MAC is %s\n", entry);

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

    if (cfg_load_network_setting(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Failed to load user plane configuration for cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_LOAD;
    }

    if (rte_cfgfile_close(file) < 0) {
        RTE_LOG(ERR, DU_UP, "Cannot close cfg file %s\n", profile_name);
        return -CFG_ERR_PROFILE_CLOSE;
    }

    return 0;
}