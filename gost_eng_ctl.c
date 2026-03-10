#include "gost_eng_ctl.h"
#include "gost_module_param.h"

int gost_control_func(ENGINE *e, int cmd, long i, void *p, void (*f) (void))
{
    int param = cmd - ENGINE_CMD_BASE;
    int ret = 0;
    if (param < 0 || param > GOST_PARAM_MAX) {
        return -1;
    }
    ret = set_default_gost_module_param(param, p);
    return ret;
}