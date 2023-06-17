#ifndef CFG_FILE_H_
#define CFG_FILE_H_

#include <rte_sched.h>
#include <rte_cfgfile.h>
#include "common.h"

#define CFG_ERR_PROFILE_NULL 1
#define CFG_ERR_PROFILE_OPEN 2
#define CFG_ERR_PROFILE_CLOSE 3
#define CFG_ERR_PROFILE_LOAD 4


int load_cfg_profile(const char *profile);

#endif /* CFG_FILE_H_ */