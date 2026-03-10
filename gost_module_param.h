#pragma once

/* Control commands */
# define GOST_PARAM_CRYPT_PARAMS 0
# define GOST_PARAM_PBE_PARAMS 1
# define GOST_PARAM_PK_FORMAT 2
# define GOST_PARAM_MAX 3

const char *get_gost_module_param(int param);
int set_default_gost_module_param(int param, const char *value);
void gost_module_params_free(void);