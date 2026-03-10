#pragma once

#include <openssl/engine.h>

# define GOST_CTRL_CRYPT_PARAMS (ENGINE_CMD_BASE+GOST_PARAM_CRYPT_PARAMS)
# define GOST_CTRL_PBE_PARAMS   (ENGINE_CMD_BASE+GOST_PARAM_PBE_PARAMS)
# define GOST_CTRL_PK_FORMAT   (ENGINE_CMD_BASE+GOST_PARAM_PK_FORMAT)

int gost_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void));